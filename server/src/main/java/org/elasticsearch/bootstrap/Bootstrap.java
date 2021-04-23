/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.bootstrap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.lucene.util.Constants;
import org.apache.lucene.util.StringHelper;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.Version;
import org.elasticsearch.cli.KeyStoreAwareCommand;
import org.elasticsearch.cli.Terminal;
import org.elasticsearch.cli.UserException;
import org.elasticsearch.common.PidFile;
import org.elasticsearch.common.SuppressForbidden;
import org.elasticsearch.common.inject.CreationException;
import org.elasticsearch.common.logging.DeprecationLogger;
import org.elasticsearch.common.logging.LogConfigurator;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.network.IfConfig;
import org.elasticsearch.common.settings.KeyStoreWrapper;
import org.elasticsearch.common.settings.SecureSettings;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.BoundTransportAddress;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.env.Environment;
import org.elasticsearch.monitor.jvm.JvmInfo;
import org.elasticsearch.monitor.os.OsProbe;
import org.elasticsearch.monitor.process.ProcessProbe;
import org.elasticsearch.node.InternalSettingsPreparer;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.NodeValidationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Internal startup code.
 */
final class Bootstrap {

    private static volatile Bootstrap INSTANCE;
    private volatile Node node;
    //主线程（前台线程）终止执行的阀门
    private final CountDownLatch keepAliveLatch = new CountDownLatch(1);
    private final Thread keepAliveThread;
    private final Spawner spawner = new Spawner();

    /** creates a new instance */
    Bootstrap() {
        //创建一个维持链接的线程
        keepAliveThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    //等待阀门打开
                    keepAliveLatch.await();
                } catch (InterruptedException e) {
                    // bail out
                }
            }
        }, "elasticsearch[keepAlive/" + Version.CURRENT + "]");
        //设置为前台线程
        keepAliveThread.setDaemon(false);
        // keep this thread alive (non daemon thread) until we shutdown
        //保持这个前台线程处于活跃状态，直到我们终止服务
        //注册shutdown的hook（钩子），保证在我们终止服务时结束这个前台线程
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                keepAliveLatch.countDown();
            }
        });
    }

    /** initialize native resources */
    //初始化本地资源
    public static void initializeNatives(Path tmpFile, boolean mlockAll, boolean systemCallFilter, boolean ctrlHandler) {
        final Logger logger = LogManager.getLogger(Bootstrap.class);

        // check if the user is running as root, and bail
        if (Natives.definitelyRunningAsRoot()) {
            throw new RuntimeException("can not run elasticsearch as root");
        }

        // enable system call filter
        if (systemCallFilter) {
            Natives.tryInstallSystemCallFilter(tmpFile);
        }

        // mlockall if requested
        if (mlockAll) {
            if (Constants.WINDOWS) {
               Natives.tryVirtualLock();
            } else {
               Natives.tryMlockall();
            }
        }

        // listener for windows close event
        if (ctrlHandler) {
            Natives.addConsoleCtrlHandler(new ConsoleCtrlHandler() {
                @Override
                public boolean handle(int code) {
                    if (CTRL_CLOSE_EVENT == code) {
                        logger.info("running graceful exit on windows");
                        try {
                            Bootstrap.stop();
                        } catch (IOException e) {
                            throw new ElasticsearchException("failed to stop node", e);
                        }
                        return true;
                    }
                    return false;
                }
            });
        }

        // force remainder of JNA to be loaded (if available).
        try {
            JNAKernel32Library.getInstance();
        } catch (Exception ignored) {
            // we've already logged this.
        }

        Natives.trySetMaxNumberOfThreads();
        Natives.trySetMaxSizeVirtualMemory();
        Natives.trySetMaxFileSize();

        // init lucene random seed. it will use /dev/urandom where available:
        StringHelper.randomId();
    }

    static void initializeProbes() {
        // Force probes to be loaded
        ProcessProbe.getInstance();
        OsProbe.getInstance();
        JvmInfo.jvmInfo();
    }

    private void setup(boolean addShutdownHook, Environment environment) throws BootstrapException {
        Settings settings = environment.settings();

        try {
            //加载当前服务模块目录下的全部插件的本地控制器，并为其创建相应的启动进程（将输入输出流挂在到jvm上）
            spawner.spawnNativeControllers(environment, true);
        } catch (IOException e) {
            throw new BootstrapException(e);
        }

        initializeNatives(
                environment.tmpFile(),
                BootstrapSettings.MEMORY_LOCK_SETTING.get(settings),
                BootstrapSettings.SYSTEM_CALL_FILTER_SETTING.get(settings),
                BootstrapSettings.CTRLHANDLER_SETTING.get(settings));

        // initialize probes before the security manager is installed
        initializeProbes();

        if (addShutdownHook) {
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override
                public void run() {
                    try {
                        IOUtils.close(node, spawner);
                        LoggerContext context = (LoggerContext) LogManager.getContext(false);
                        Configurator.shutdown(context);
                        if (node != null && node.awaitClose(10, TimeUnit.SECONDS) == false) {
                            throw new IllegalStateException("Node didn't stop within 10 seconds. " +
                                    "Any outstanding requests or tasks might get killed.");
                        }
                    } catch (IOException ex) {
                        throw new ElasticsearchException("failed to stop node", ex);
                    } catch (InterruptedException e) {
                        LogManager.getLogger(Bootstrap.class).warn("Thread got interrupted while waiting for the node to shutdown.");
                        Thread.currentThread().interrupt();
                    }
                }
            });
        }

        try {
            // look for jar hell
            final Logger logger = LogManager.getLogger(JarHell.class);
            JarHell.checkJarHell(logger::debug);
        } catch (IOException | URISyntaxException e) {
            throw new BootstrapException(e);
        }

        // Log ifconfig output before SecurityManager is installed
        IfConfig.logIfNecessary();

        // install SM after natives, shutdown hooks, etc.
        try {
            Security.configure(environment, BootstrapSettings.SECURITY_FILTER_BAD_DEFAULTS_SETTING.get(settings));
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new BootstrapException(e);
        }

        node = new Node(environment) {
            @Override
            protected void validateNodeBeforeAcceptingRequests(
                final BootstrapContext context,
                final BoundTransportAddress boundTransportAddress, List<BootstrapCheck> checks) throws NodeValidationException {
                BootstrapChecks.check(context, boundTransportAddress, checks);
            }
        };
    }

    static SecureSettings loadSecureSettings(Environment initialEnv) throws BootstrapException {
        final KeyStoreWrapper keystore;
        try {
            //加载elasticsearch.keystore文件并解析得到KeyStoreWrapper对象
            keystore = KeyStoreWrapper.load(initialEnv.configFile());
        } catch (IOException e) {
            throw new BootstrapException(e);
        }
        //获取安全认证密码
        SecureString password;
        try {
            if (keystore != null && keystore.hasPassword()) {
                password = readPassphrase(System.in, KeyStoreAwareCommand.MAX_PASSPHRASE_LENGTH);
            } else {
                password = new SecureString(new char[0]);
            }
        } catch (IOException e) {
            throw new BootstrapException(e);
        }

        try{
            //如果配置目录下没有密钥存储库文件，则创建，并将生成密钥写入
            if (keystore == null) {
                final KeyStoreWrapper keyStoreWrapper = KeyStoreWrapper.create();
                keyStoreWrapper.save(initialEnv.configFile(), new char[0]);
                return keyStoreWrapper;
            } else {
                //如果存在存储库文件，则对其进行解密，并在需要的情况下对其格式进行升级
                keystore.decrypt(password.getChars());
                KeyStoreWrapper.upgrade(keystore, initialEnv.configFile(), password.getChars());
            }
        } catch (Exception e) {
            throw new BootstrapException(e);
        } finally {
            //释放资源
            password.close();
        }
        return keystore;
    }

    // visible for tests
    /**
     * Read from an InputStream up to the first carriage return or newline,
     * returning no more than maxLength characters.
     */
    static SecureString readPassphrase(InputStream stream, int maxLength) throws IOException {
        SecureString passphrase;

        try(InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
            passphrase = new SecureString(Terminal.readLineToCharArray(reader, maxLength));
        } catch (RuntimeException e) {
            if (e.getMessage().startsWith("Input exceeded maximum length")) {
                throw new IllegalStateException("Password exceeded maximum length of " + maxLength, e);
            }
            throw e;
        }

        if (passphrase.length() == 0) {
            passphrase.close();
            throw new IllegalStateException("Keystore passphrase required but none provided.");
        }

        return passphrase;
    }

    private static Environment createEnvironment(
            final Path pidFile,
            final SecureSettings secureSettings,
            final Settings initialSettings,
            final Path configPath) {
        //创建设置构建器
        Settings.Builder builder = Settings.builder();
        //将pidfile设置添加到构建器中
        if (pidFile != null) {
            builder.put(Environment.NODE_PIDFILE_SETTING.getKey(), pidFile);
        }
        //将初始化设置（启动参数中的设置，以及配置文件配置的设置）添加到构建器中
        builder.put(initialSettings);
        //将安全设置添加到构建器中
        if (secureSettings != null) {
            builder.setSecureSettings(secureSettings);
        }
        //解析全部配置（命令行、系统属性、系统环境变量以及服务配置文件），并创建Environment对象，返回
        return InternalSettingsPreparer.prepareEnvironment(builder.build(), Collections.emptyMap(), configPath,
                // HOSTNAME is set by elasticsearch-env and elasticsearch-env.bat so it is always available
                () -> System.getenv("HOSTNAME"));
    }

    private void start() throws NodeValidationException {
        node.start();
        keepAliveThread.start();
    }

    static void stop() throws IOException {
        try {
            IOUtils.close(INSTANCE.node, INSTANCE.spawner);
            if (INSTANCE.node != null && INSTANCE.node.awaitClose(10, TimeUnit.SECONDS) == false) {
                throw new IllegalStateException("Node didn't stop within 10 seconds. Any outstanding requests or tasks might get killed.");
            }
        } catch (InterruptedException e) {
            LogManager.getLogger(Bootstrap.class).warn("Thread got interrupted while waiting for the node to shutdown.");
            Thread.currentThread().interrupt();
        } finally {
            INSTANCE.keepAliveLatch.countDown();
        }
    }

    /**
     * This method is invoked by {@link Elasticsearch#main(String[])} to startup elasticsearch.
     * 启动elasticsearch服务
     */
    static void init(
            final boolean foreground,
            final Path pidFile,
            final boolean quiet,
            final Environment initialEnv) throws BootstrapException, NodeValidationException, UserException {
        // force the class initializer for BootstrapInfo to run before
        // the security manager is installed
        //在安装安全管理器之前强制运行BootstrapInfo的类初始化器（目前为空方法）
        BootstrapInfo.init();
        //创建启动服务的引导实例化对象
        INSTANCE = new Bootstrap();
        //通过加载配置路径下的elasticsearch.keystore文件来获取到服务的安全设置
        final SecureSettings keystore = loadSecureSettings(initialEnv);
        //解析全部配置，并创建Environment对象
        final Environment environment = createEnvironment(pidFile, keystore, initialEnv.settings(), initialEnv.configFile());
        //配置日志中的节点名称为当前设置中的节点名称
        LogConfigurator.setNodeName(Node.NODE_NAME_SETTING.get(environment.settings()));
        try {
            //通过我们对服务的一些配置，来对logger对象进行配置 （logger配置失败，直接终止服务）
            LogConfigurator.configure(environment);
        } catch (IOException e) {
            throw new BootstrapException(e);
        }
        //从系统属性java.specification.version中获取当前系统环境变量下使用的jdk版本
        //启动此版本的服务需要jdk11以上的版本
        if (JavaVersion.current().compareTo(JavaVersion.parse("11")) < 0) {
            final String message = String.format(
                            Locale.ROOT,
                            "future versions of Elasticsearch will require Java 11; " +
                                    "your Java version from [%s] does not meet this requirement",
                            System.getProperty("java.home"));
            DeprecationLogger.getLogger(Bootstrap.class).deprecate("java_version_11_required", message);
        }
        //如果配置了pidfile路径，则进行创建,并将服务进程的pid写入
        if (environment.pidFile() != null) {
            try {
                PidFile.create(environment.pidFile(), true);
            } catch (IOException e) {
                throw new BootstrapException(e);
            }
        }
        //如果服务是守护进程运行，或者是静音模式，则关闭标准输出流
        final boolean closeStandardStreams = (foreground == false) || quiet;
        try {
            //从当前root logger对象中移除标准输出流（ConsoleAppender和system.out）
            if (closeStandardStreams) {
                final Logger rootLogger = LogManager.getRootLogger();
                final Appender maybeConsoleAppender = Loggers.findAppender(rootLogger, ConsoleAppender.class);
                if (maybeConsoleAppender != null) {
                    Loggers.removeAppender(rootLogger, maybeConsoleAppender);
                }
                closeSystOut();
            }

            // fail if somebody replaced the lucene jars
            //检测当前使用的lucene jar版本是否与当前服务要求匹配
            checkLucene();

            // install the default uncaught exception handler; must be done before security is
            // initialized as we do not want to grant the runtime permission
            // setDefaultUncaughtExceptionHandler
            //安装默认的未捕获异常处理器，必须在安全性初始化之前进行设置，因为我们不想授予其运行时权限
            Thread.setDefaultUncaughtExceptionHandler(new ElasticsearchUncaughtExceptionHandler());

            INSTANCE.setup(true, environment);

            try {
                // any secure settings must be read during node construction
                //释放安全设置资源
                IOUtils.close(keystore);
            } catch (IOException e) {
                throw new BootstrapException(e);
            }

            INSTANCE.start();

            // We don't close stderr if `--quiet` is passed, because that
            // hides fatal startup errors. For example, if Elasticsearch is
            // running via systemd, the init script only specifies
            // `--quiet`, not `-d`, so we want users to be able to see
            // startup errors via journalctl.
            //如果服务是后台运行的，则关闭system.err输出流
            if (foreground == false) {
                closeSysError();
            }
        } catch (NodeValidationException | RuntimeException e) {
            // disable console logging, so user does not see the exception twice (jvm will show it already)
            final Logger rootLogger = LogManager.getRootLogger();
            final Appender maybeConsoleAppender = Loggers.findAppender(rootLogger, ConsoleAppender.class);
            if (foreground && maybeConsoleAppender != null) {
                Loggers.removeAppender(rootLogger, maybeConsoleAppender);
            }
            Logger logger = LogManager.getLogger(Bootstrap.class);
            // HACK, it sucks to do this, but we will run users out of disk space otherwise
            if (e instanceof CreationException) {
                // guice: log the shortened exc to the log file
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                PrintStream ps = null;
                try {
                    ps = new PrintStream(os, false, "UTF-8");
                } catch (UnsupportedEncodingException uee) {
                    assert false;
                    e.addSuppressed(uee);
                }
                new StartupException(e).printStackTrace(ps);
                ps.flush();
                try {
                    logger.error("Guice Exception: {}", os.toString("UTF-8"));
                } catch (UnsupportedEncodingException uee) {
                    assert false;
                    e.addSuppressed(uee);
                }
            } else if (e instanceof NodeValidationException) {
                logger.error("node validation exception\n{}", e.getMessage());
            } else {
                // full exception
                logger.error("Exception", e);
            }
            // re-enable it if appropriate, so they can see any logging during the shutdown process
            if (foreground && maybeConsoleAppender != null) {
                Loggers.addAppender(rootLogger, maybeConsoleAppender);
            }

            throw e;
        }
    }

    @SuppressForbidden(reason = "System#out")
    private static void closeSystOut() {
        System.out.close();
    }

    @SuppressForbidden(reason = "System#err")
    private static void closeSysError() {
        System.err.close();
    }

    private static void checkLucene() {
        if (Version.CURRENT.luceneVersion.equals(org.apache.lucene.util.Version.LATEST) == false) {
            throw new AssertionError("Lucene version mismatch this version of Elasticsearch requires lucene version ["
                + Version.CURRENT.luceneVersion + "]  but the current lucene version is [" + org.apache.lucene.util.Version.LATEST + "]");
        }
    }

}
