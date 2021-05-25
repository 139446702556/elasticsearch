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

package org.elasticsearch.plugins;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.analysis.util.CharFilterFactory;
import org.apache.lucene.analysis.util.TokenFilterFactory;
import org.apache.lucene.analysis.util.TokenizerFactory;
import org.apache.lucene.codecs.Codec;
import org.apache.lucene.codecs.DocValuesFormat;
import org.apache.lucene.codecs.PostingsFormat;
import org.apache.lucene.util.SPIClassIterator;
import org.elasticsearch.Build;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.Version;
import org.elasticsearch.action.admin.cluster.node.info.PluginsAndModules;
import org.elasticsearch.bootstrap.JarHell;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.common.io.FileSystemUtils;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Setting.Property;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexModule;
import org.elasticsearch.node.ReportingService;
import org.elasticsearch.threadpool.ExecutorBuilder;
import org.elasticsearch.transport.TransportSettings;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.elasticsearch.common.io.FileSystemUtils.isAccessibleDirectory;

public class PluginsService implements ReportingService<PluginsAndModules> {

    private static final Logger logger = LogManager.getLogger(PluginsService.class);

    private final Settings settings;
    private final Path configPath;

    /**
     * We keep around a list of plugins and modules
     */
    private final List<Tuple<PluginInfo, Plugin>> plugins;
    private final PluginsAndModules info;

    public static final Setting<List<String>> MANDATORY_SETTING =
        Setting.listSetting("plugin.mandatory", Collections.emptyList(), Function.identity(), Property.NodeScope);

    public List<Setting<?>> getPluginSettings() {
        return plugins.stream().flatMap(p -> p.v2().getSettings().stream()).collect(Collectors.toList());
    }

    public List<String> getPluginSettingsFilter() {
        return plugins.stream().flatMap(p -> p.v2().getSettingsFilter().stream()).collect(Collectors.toList());
    }

    /**
     * Constructs a new PluginService
     * 构建一个新的pluginService对象
     * @param settings The settings of the system
     * @param modulesDirectory The directory modules exist in, or null if modules should not be loaded from the filesystem
     * @param pluginsDirectory The directory plugins exist in, or null if plugins should not be loaded from the filesystem
     * @param classpathPlugins Plugins that exist in the classpath which should be loaded
     *                         类路径中存在（设置）的应该加载的插件
     */
    public PluginsService(
        Settings settings,
        Path configPath,
        Path modulesDirectory,
        Path pluginsDirectory,
        Collection<Class<? extends Plugin>> classpathPlugins
    ) {
        this.settings = settings;
        this.configPath = configPath;

        List<Tuple<PluginInfo, Plugin>> pluginsLoaded = new ArrayList<>();
        List<PluginInfo> pluginsList = new ArrayList<>();
        // we need to build a List of plugins for checking mandatory plugins
        // 我们需要建立一个插件列表，以便检测强制性插件
        final List<String> pluginsNames = new ArrayList<>();
        // first we load plugins that are on the classpath. this is for tests and transport clients
        // 首先我们加载在classpath上的插件，这是针对测试和transport客户端的
        for (Class<? extends Plugin> pluginClass : classpathPlugins) {
            // 通过反射来创建指定插件的实例化对象
            Plugin plugin = loadPlugin(pluginClass, settings, configPath);
            // 构建pluginInfo对象
            PluginInfo pluginInfo = new PluginInfo(pluginClass.getName(), "classpath plugin", "NA", Version.CURRENT, "1.8",
                                                   pluginClass.getName(), Collections.emptyList(), false);
            if (logger.isTraceEnabled()) {
                logger.trace("plugin loaded from classpath [{}]", pluginInfo);
            }
            // 将加载成功的插件添加到指定容器中
            pluginsLoaded.add(new Tuple<>(pluginInfo, plugin));
            pluginsList.add(pluginInfo);
            pluginsNames.add(pluginInfo.getName());
        }
        //保存在服务内部加载的全部模块和插件
        Set<Bundle> seenBundles = new LinkedHashSet<>();
        //用于保存加载的模块信息列表
        List<PluginInfo> modulesList = new ArrayList<>();
        // load modules
        // 加载modules目录的模块（加载各模块的属性信息和jar文件url）
        if (modulesDirectory != null) {
            try {
                Set<Bundle> modules = getModuleBundles(modulesDirectory);
                for (Bundle bundle : modules) {
                    modulesList.add(bundle.plugin);
                }
                seenBundles.addAll(modules);
            } catch (IOException ex) {
                throw new IllegalStateException("Unable to initialize modules", ex);
            }
        }

        // now, find all the ones that are in plugins/
        // 加载plugins中的所有插件
        if (pluginsDirectory != null) {
            try {
                // TODO: remove this leniency, but tests bogusly rely on it
                // 是否为一个可访问目录
                if (isAccessibleDirectory(pluginsDirectory, logger)) {
                    // 检测是否存在移除失败的插件
                    checkForFailedPluginRemovals(pluginsDirectory);
                    // 加载es服务中plugins目录中的全部插件
                    Set<Bundle> plugins = getPluginBundles(pluginsDirectory);
                    for (final Bundle bundle : plugins) {
                        pluginsList.add(bundle.plugin);
                        pluginsNames.add(bundle.plugin.getName());
                    }
                    seenBundles.addAll(plugins);
                }
            } catch (IOException ex) {
                throw new IllegalStateException("Unable to initialize plugins", ex);
            }
        }
        //加载全部模块与插件的jar包（包括加载插件中包含的扩展插件），已得到对应的plugin对象，并且根据插件具体情况来重新加载lucene spi来对插件中包含的编解码器和分析器进行加载
        List<Tuple<PluginInfo, Plugin>> loaded = loadBundles(seenBundles);
        pluginsLoaded.addAll(loaded);
        // 创建服务中全部插件和模块集合组成的完整信息对象
        this.info = new PluginsAndModules(pluginsList, modulesList);
        // 根据加载的全部插件对象集合创建其对应的不可变视图
        this.plugins = Collections.unmodifiableList(pluginsLoaded);

        // Checking expected plugins
        // 检测预期插件（强制性要加载的）
        List<String> mandatoryPlugins = MANDATORY_SETTING.get(settings);
        // 检测强制性加载插件是否已经加载，如果有未加载的，则抛出异常
        if (mandatoryPlugins.isEmpty() == false) {
            Set<String> missingPlugins = new HashSet<>();
            for (String mandatoryPlugin : mandatoryPlugins) {
                if (!pluginsNames.contains(mandatoryPlugin) && !missingPlugins.contains(mandatoryPlugin)) {
                    missingPlugins.add(mandatoryPlugin);
                }
            }
            if (!missingPlugins.isEmpty()) {
                final String message = String.format(
                        Locale.ROOT,
                        "missing mandatory plugins [%s], found plugins [%s]",
                        Strings.collectionToDelimitedString(missingPlugins, ", "),
                        Strings.collectionToDelimitedString(pluginsNames, ", "));
                throw new IllegalStateException(message);
            }
        }

        // we don't log jars in lib/ we really shouldn't log modules,
        // but for now: just be transparent so we can debug any potential issues
        // 通过日志或控制台打印出当前加载的全部模块和插件名称
        logPluginInfo(info.getModuleInfos(), "module", logger);
        logPluginInfo(info.getPluginInfos(), "plugin", logger);
    }

    private static void logPluginInfo(final List<PluginInfo> pluginInfos, final String type, final Logger logger) {
        assert pluginInfos != null;
        if (pluginInfos.isEmpty()) {
            logger.info("no " + type + "s loaded");
        } else {
            for (final String name : pluginInfos.stream().map(PluginInfo::getName).sorted().collect(Collectors.toList())) {
                logger.info("loaded " + type + " [" + name + "]");
            }
        }
    }

    //检测插件们的setting和feature相关信息是否出现重复（不合理），如果存在，则终止程序；否则合并当前属性与新增的插件标记属性，并返回
    public Settings updatedSettings() {
        Map<String, String> foundSettings = new HashMap<>();
        final Map<String, String> features = new TreeMap<>();
        final Settings.Builder builder = Settings.builder();
        // 遍历全部已经加载的插件
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            // 获取当前插件的设置
            Settings settings = plugin.v2().additionalSettings();
            // 检测在不同的插件settings中是否存在相同的设置属性，存在则引发异常（同一个服务中只允许一个属性出现一次，否则会被覆盖）
            for (String setting : settings.keySet()) {
                String oldPlugin = foundSettings.put(setting, plugin.v1().getName());
                if (oldPlugin != null) {
                    throw new IllegalArgumentException("Cannot have additional setting [" + setting + "] " +
                        "in plugin [" + plugin.v1().getName() + "], already added in plugin [" + oldPlugin + "]");
                }
            }
            //将插件settings添加到builder中
            builder.put(settings);
            // 检测插件的特征信息，此信息不允许出现多个插件相同的情况
            final Optional<String> maybeFeature = plugin.v2().getFeature();
            if (maybeFeature.isPresent()) {
                final String feature = maybeFeature.get();
                if (features.containsKey(feature)) {
                    final String message = String.format(
                            Locale.ROOT,
                            "duplicate feature [%s] in plugin [%s], already added in [%s]",
                            feature,
                            plugin.v1().getName(),
                            features.get(feature));
                    throw new IllegalArgumentException(message);
                }
                features.put(feature, plugin.v1().getName());
            }
        }
        // 根据各个插件的feature进行条件标记属性，用来标记已经加载过的plugin
        for (final String feature : features.keySet()) {
            builder.put(TransportSettings.FEATURE_PREFIX + "." + feature, true);
        }
        // 合并标记属性和设置的相关属性
        return builder.put(this.settings).build();
    }

    public Collection<Module> createGuiceModules() {
        List<Module> modules = new ArrayList<>();
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            modules.addAll(plugin.v2().createGuiceModules());
        }
        return modules;
    }

    public List<ExecutorBuilder<?>> getExecutorBuilders(Settings settings) {
        final ArrayList<ExecutorBuilder<?>> builders = new ArrayList<>();
        for (final Tuple<PluginInfo, Plugin> plugin : plugins) {
            builders.addAll(plugin.v2().getExecutorBuilders(settings));
        }
        return builders;
    }

    /** Returns all classes injected into guice by plugins which extend {@link LifecycleComponent}. */
    public Collection<Class<? extends LifecycleComponent>> getGuiceServiceClasses() {
        List<Class<? extends LifecycleComponent>> services = new ArrayList<>();
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            services.addAll(plugin.v2().getGuiceServiceClasses());
        }
        return services;
    }

    public void onIndexModule(IndexModule indexModule) {
        for (Tuple<PluginInfo, Plugin> plugin : plugins) {
            plugin.v2().onIndexModule(indexModule);
        }
    }

    /**
     * Get information about plugins and modules
     */
    @Override
    public PluginsAndModules info() {
        return info;
    }

    // a "bundle" is a group of jars in a single classloader
    // 表示在一个单独的classloader中一组捆绑的jar包（即一个模块或者插件的中包含的全部jar包）
    static class Bundle {
        final PluginInfo plugin;
        final Set<URL> urls;

        Bundle(PluginInfo plugin, Path dir) throws IOException {
            this.plugin = Objects.requireNonNull(plugin);
            Set<URL> urls = new LinkedHashSet<>();
            // gather urls for jar files
            // 获取给定路径中的全部jar文件的路径url集合
            try (DirectoryStream<Path> jarStream = Files.newDirectoryStream(dir, "*.jar")) {
                for (Path jar : jarStream) {
                    // normalize with toRealPath to get symlinks out of our hair
                    URL url = jar.toRealPath().toUri().toURL();
                    if (urls.add(url) == false) {
                        throw new IllegalStateException("duplicate codebase: " + url);
                    }
                }
            }
            this.urls = Objects.requireNonNull(urls);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Bundle bundle = (Bundle) o;
            return Objects.equals(plugin, bundle.plugin);
        }

        @Override
        public int hashCode() {
            return Objects.hash(plugin);
        }
    }

    /**
     * Extracts all installed plugin directories from the provided {@code rootPath}.
     * 从提供的rootpath中获取到全部已经安装的插件目录
     * @param rootPath the path where the plugins are installed
     * @return a list of all plugin paths installed in the {@code rootPath}
     * @throws IOException if an I/O exception occurred reading the directories
     */
    public static List<Path> findPluginDirs(final Path rootPath) throws IOException {
        final List<Path> plugins = new ArrayList<>();
        final Set<String> seen = new HashSet<>();
        if (Files.exists(rootPath)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(rootPath)) {
                for (Path plugin : stream) {
                    if (FileSystemUtils.isDesktopServicesStore(plugin) ||
                        plugin.getFileName().toString().startsWith(".removing-")) {
                        continue;
                    }
                    if (seen.add(plugin.getFileName().toString()) == false) {
                        throw new IllegalStateException("duplicate plugin: " + plugin);
                    }
                    plugins.add(plugin);
                }
            }
        }
        return plugins;
    }

    /**
     * Verify the given plugin is compatible with the current Elasticsearch installation.
     * 验证给定的插件是否与当前版本的es服务兼容
     */
    static void verifyCompatibility(PluginInfo info) {
        // 检测插件要求的es版本是否与当前服务一致
        if (info.getElasticsearchVersion().equals(Version.CURRENT) == false) {
            throw new IllegalArgumentException("Plugin [" + info.getName() + "] was built for Elasticsearch version "
                + info.getElasticsearchVersion() + " but version " + Version.CURRENT + " is running");
        }
        // 检测当前使用的jdk版本是否大于等于要求版本
        JarHell.checkJavaVersion(info.getName(), info.getJavaVersion());
    }

    static void checkForFailedPluginRemovals(final Path pluginsDirectory) throws IOException {
        /*
         * Check for the existence of a marker file that indicates any plugins are in a garbage state from a failed attempt to remove the
         * plugin.
         * 检测是否存在包含removing-的标识的目录文件，当插件处于尝试删除失败时，则会产生此状态
         * 如果存在垃圾插件，则终止服务
         */
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(pluginsDirectory, ".removing-*")) {
            final Iterator<Path> iterator = stream.iterator();
            if (iterator.hasNext()) {
                final Path removing = iterator.next();
                final String fileName = removing.getFileName().toString();
                final String name = fileName.substring(1 + fileName.indexOf("-"));
                final String message = String.format(
                        Locale.ROOT,
                        "found file [%s] from a failed attempt to remove the plugin [%s]; execute [elasticsearch-plugin remove %2$s]",
                        removing,
                        name);
                throw new IllegalStateException(message);
            }
        }
    }

    /** Get bundles for plugins installed in the given modules directory. */
    static Set<Bundle> getModuleBundles(Path modulesDirectory) throws IOException {
        return findBundles(modulesDirectory, "module");
    }

    /** Get bundles for plugins installed in the given plugins directory. */
    static Set<Bundle> getPluginBundles(final Path pluginsDirectory) throws IOException {
        return findBundles(pluginsDirectory, "plugin");
    }

    // searches subdirectories under the given directory for plugin directories
    // 将给定路径中的所有模块加载为一个个对应的bundle对象
    private static Set<Bundle> findBundles(final Path directory, String type) throws IOException {
        final Set<Bundle> bundles = new HashSet<>();
        for (final Path plugin : findPluginDirs(directory)) {
            if (plugin.toFile().isFile()){
                continue;
            }
            final Bundle bundle = readPluginBundle(bundles, plugin, type);
            bundles.add(bundle);
        }

        return bundles;
    }

    // get a bundle for a single plugin dir
    // 从一个指定的模块路径中获取相关信息来创建得到一个bundle对象
    private static Bundle readPluginBundle(final Set<Bundle> bundles, final Path plugin, String type) throws IOException {
        LogManager.getLogger(PluginsService.class).trace("--- adding [{}] [{}]", type, plugin.toAbsolutePath());
        final PluginInfo info;
        try {
            // 从模块的plugin-descriptor.properties文件中加载信息得到pluginInfo对象
            info = PluginInfo.readFromProperties(plugin);
        } catch (final IOException e) {
            throw new IllegalStateException("Could not load plugin descriptor for " + type +
                                            " directory [" + plugin.getFileName() + "]", e);
        }
        // 创建此模块（插件）对应的bundle（捆绑包）对象（此对象保存了插件的属性信息和包含的全部jar文件路径）
        final Bundle bundle = new Bundle(info, plugin);
        // 判断此模块是否重复，或者是否不是正式版本（module不能为非正式版，插件可以），如果满足其一则抛出异常终止服务
        if (bundles.add(bundle) == false) {
            throw new IllegalStateException("duplicate " + type + ": " + info);
        }
        if (type.equals("module") && info.getName().startsWith("test-") && Build.CURRENT.isSnapshot() == false) {
            throw new IllegalStateException("external test module [" + plugin.getFileName() + "] found in non-snapshot build");
        }
        return bundle;
    }

    /**
     * Return the given bundles, sorted in dependency loading order.
     * 返回按照加载依赖项排序的bundles
     * This sort is stable, so that if two plugins do not have any interdependency,
     * their relative order from iteration of the provided set will not change.
     *
     * @throws IllegalStateException if a dependency cycle is found
     */
    // pkg private for tests
    static List<Bundle> sortBundles(Set<Bundle> bundles) {
        Map<String, Bundle> namedBundles = bundles.stream().collect(Collectors.toMap(b -> b.plugin.getName(), Function.identity()));
        LinkedHashSet<Bundle> sortedBundles = new LinkedHashSet<>();
        LinkedHashSet<String> dependencyStack = new LinkedHashSet<>();
        for (Bundle bundle : bundles) {
            addSortedBundle(bundle, namedBundles, sortedBundles, dependencyStack);
        }
        return new ArrayList<>(sortedBundles);
    }

    // add the given bundle to the sorted bundles, first adding dependencies
    // 将给定的包添加到已排序的包中，首先先添加依赖
    private static void addSortedBundle(Bundle bundle, Map<String, Bundle> bundles, LinkedHashSet<Bundle> sortedBundles,
                                        LinkedHashSet<String> dependencyStack) {
        // 获取插件name
        String name = bundle.plugin.getName();
        // 判断当前插件是否已经出现在依赖栈中，存在则抛出异常
        if (dependencyStack.contains(name)) {
            StringBuilder msg = new StringBuilder("Cycle found in plugin dependencies: ");
            dependencyStack.forEach(s -> {
                msg.append(s);
                msg.append(" -> ");
            });
            msg.append(name);
            throw new IllegalStateException(msg.toString());
        }
        //bundle已存在sortedBundles中，则忽略
        if (sortedBundles.contains(bundle)) {
            // already added this plugin, via a dependency
            return;
        }
        //避免插件之间出现循环依赖
        dependencyStack.add(name);
        // 遍历当前插件的扩展插件
        for (String dependency : bundle.plugin.getExtendedPlugins()) {
            //如果扩展插件在已配置插件中不存在，则终止执行
            Bundle depBundle = bundles.get(dependency);
            if (depBundle == null) {
                throw new IllegalArgumentException("Missing plugin [" + dependency + "], dependency of [" + name + "]");
            }
            // 递归 对扩展插件的依赖项进行遍历
            addSortedBundle(depBundle, bundles, sortedBundles, dependencyStack);
            assert sortedBundles.contains(depBundle);
        }
        dependencyStack.remove(name);
        //从最终的依赖插件开始进行添加到排序队列里
        sortedBundles.add(bundle);
    }

    private List<Tuple<PluginInfo,Plugin>> loadBundles(Set<Bundle> bundles) {
        //存放被加载得到的插件信息和对应插件对象
        List<Tuple<PluginInfo, Plugin>> plugins = new ArrayList<>();
        // 已经加载的插件
        Map<String, Plugin> loaded = new HashMap<>();
        Map<String, Set<URL>> transitiveUrls = new HashMap<>();
        // 按照插件的原有循序和依赖关系进行排序
        List<Bundle> sortedBundles = sortBundles(bundles);
        //遍历所有插件的捆绑包
        for (Bundle bundle : sortedBundles) {
            // 检查插件与其扩展插件中的全部jar包，防止出现重复
            checkBundleJarHell(JarHell.parseClassPath(), bundle, transitiveUrls);
            // 加载插件
            final Plugin plugin = loadBundle(bundle, loaded);
            // 添加加载的plugin到容器中
            plugins.add(new Tuple<>(bundle.plugin, plugin));
        }
        // 加载插件中包含的扩展插件
        loadExtensions(plugins);
        // 创建插件集合快照并返回
        return Collections.unmodifiableList(plugins);
    }

    // package-private for test visibility
    static void loadExtensions(List<Tuple<PluginInfo, Plugin>> plugins) {
        Map<String, List<Plugin>> extendingPluginsByName = plugins.stream()
            .flatMap(t -> t.v1().getExtendedPlugins().stream().map(extendedPlugin -> Tuple.tuple(extendedPlugin, t.v2())))
            .collect(Collectors.groupingBy(Tuple::v1, Collectors.mapping(Tuple::v2, Collectors.toList())));
        for (Tuple<PluginInfo, Plugin> pluginTuple : plugins) {
            if (pluginTuple.v2() instanceof ExtensiblePlugin) {
                loadExtensionsForPlugin((ExtensiblePlugin) pluginTuple.v2(),
                    extendingPluginsByName.getOrDefault(pluginTuple.v1().getName(), Collections.emptyList()));
            }
        }
    }

    private static void loadExtensionsForPlugin(ExtensiblePlugin extensiblePlugin, List<Plugin> extendingPlugins) {
        ExtensiblePlugin.ExtensionLoader extensionLoader = new ExtensiblePlugin.ExtensionLoader() {
            @Override
            public <T> List<T> loadExtensions(Class<T> extensionPointType) {
                List<T> result = new ArrayList<>();
                for (Plugin extendingPlugin : extendingPlugins) {
                    result.addAll(createExtensions(extensionPointType, extendingPlugin));
                }
                return Collections.unmodifiableList(result);
            }
        };

        extensiblePlugin.loadExtensions(extensionLoader);
    }

    private static <T> List<? extends T> createExtensions(Class<T> extensionPointType, Plugin plugin) {
        SPIClassIterator<T> classIterator = SPIClassIterator.get(extensionPointType, plugin.getClass().getClassLoader());
        List<T> extensions = new ArrayList<>();
        while (classIterator.hasNext()) {
            Class<? extends T> extensionClass = classIterator.next();
            extensions.add(createExtension(extensionClass, extensionPointType, plugin));
        }
        return extensions;
    }

    // package-private for test visibility
    static <T> T createExtension(Class<? extends T> extensionClass, Class<T> extensionPointType, Plugin plugin) {
        //noinspection unchecked
        Constructor<T>[] constructors = (Constructor<T>[]) extensionClass.getConstructors();
        if (constructors.length == 0) {
            throw new IllegalStateException("no public " + extensionConstructorMessage(extensionClass, extensionPointType));
        }

        if (constructors.length > 1) {
            throw new IllegalStateException("no unique public " + extensionConstructorMessage(extensionClass, extensionPointType));
        }

        final Constructor<T> constructor = constructors[0];
        if (constructor.getParameterCount() > 1) {
            throw new IllegalStateException(extensionSignatureMessage(extensionClass, extensionPointType, plugin));
        }

        if (constructor.getParameterCount() == 1 && constructor.getParameterTypes()[0] != plugin.getClass()) {
            throw new IllegalStateException(extensionSignatureMessage(extensionClass, extensionPointType, plugin) +
                ", not (" + constructor.getParameterTypes()[0].getName() + ")");
        }

        try {
            if (constructor.getParameterCount() == 0) {
                return constructor.newInstance();
            } else {
                return constructor.newInstance(plugin);
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(
                "failed to create extension [" + extensionClass.getName() + "] of type [" + extensionPointType.getName() + "]", e
            );
        }
    }

    private static <T> String extensionSignatureMessage(Class<? extends T> extensionClass, Class<T> extensionPointType, Plugin plugin) {
        return "signature of " + extensionConstructorMessage(extensionClass, extensionPointType) +
            " must be either () or (" + plugin.getClass().getName() + ")";
    }

    private static <T> String extensionConstructorMessage(Class<? extends T> extensionClass, Class<T> extensionPointType) {
        return "constructor for extension [" + extensionClass.getName() + "] of type [" + extensionPointType.getName() + "]";
    }

    // jar-hell check the bundle against the parent classloader and extended plugins
    // the plugin cli does it, but we do it again, in case users mess with jar files manually
    static void checkBundleJarHell(Set<URL> classpath, Bundle bundle, Map<String, Set<URL>> transitiveUrls) {
        // invariant: any plugins this plugin bundle extends have already been added to transitiveUrls
        // 获取插件的扩展插件
        List<String> exts = bundle.plugin.getExtendedPlugins();

        try {
            final Logger logger = LogManager.getLogger(JarHell.class);
            Set<URL> urls = new HashSet<>();
            // 遍历扩展插件
            for (String extendedPlugin : exts) {
                Set<URL> pluginUrls = transitiveUrls.get(extendedPlugin);
                assert pluginUrls != null : "transitive urls should have already been set for " + extendedPlugin;

                Set<URL> intersection = new HashSet<>(urls);
                intersection.retainAll(pluginUrls);
                if (intersection.isEmpty() == false) {
                    throw new IllegalStateException("jar hell! extended plugins " + exts +
                                                    " have duplicate codebases with each other: " + intersection);
                }

                intersection = new HashSet<>(bundle.urls);
                intersection.retainAll(pluginUrls);
                if (intersection.isEmpty() == false) {
                    throw new IllegalStateException("jar hell! duplicate codebases with extended plugin [" +
                                                    extendedPlugin + "]: " + intersection);
                }

                urls.addAll(pluginUrls);
                JarHell.checkJarHell(urls, logger::debug); // check jarhell as we add each extended plugin's urls
            }

            urls.addAll(bundle.urls);
            JarHell.checkJarHell(urls, logger::debug); // check jarhell of each extended plugin against this plugin
            transitiveUrls.put(bundle.plugin.getName(), urls);

            // check we don't have conflicting codebases with core
            Set<URL> intersection = new HashSet<>(classpath);
            intersection.retainAll(bundle.urls);
            if (intersection.isEmpty() == false) {
                throw new IllegalStateException("jar hell! duplicate codebases between plugin and core: " + intersection);
            }
            // check we don't have conflicting classes
            Set<URL> union = new HashSet<>(classpath);
            union.addAll(bundle.urls);
            JarHell.checkJarHell(union, logger::debug);
        } catch (Exception e) {
            throw new IllegalStateException("failed to load plugin " + bundle.plugin.getName() + " due to jar hell", e);
        }
    }

    private Plugin loadBundle(Bundle bundle, Map<String, Plugin> loaded) {
        //获取插件名
        String name = bundle.plugin.getName();
        // 校验安装插件是否与当前环境匹配
        verifyCompatibility(bundle.plugin);

        // collect loaders of extended plugins
        // 收集扩展插件的加载器
        List<ClassLoader> extendedLoaders = new ArrayList<>();
        //遍历扩展插件，判断其是否已经加载完成，并将其classloader添加到extendedLoaders容器中
        for (String extendedPluginName : bundle.plugin.getExtendedPlugins()) {
            Plugin extendedPlugin = loaded.get(extendedPluginName);
            assert extendedPlugin != null;
            if (ExtensiblePlugin.class.isInstance(extendedPlugin) == false) {
                throw new IllegalStateException("Plugin [" + name + "] cannot extend non-extensible plugin [" + extendedPluginName + "]");
            }
            extendedLoaders.add(extendedPlugin.getClass().getClassLoader());
        }

        // create a child to load the plugin in this bundle
        // 在当前包中创建一个子类加载器来加载插件
        ClassLoader parentLoader = PluginLoaderIndirection.createLoader(getClass().getClassLoader(), extendedLoaders);
        ClassLoader loader = URLClassLoader.newInstance(bundle.urls.toArray(new URL[0]), parentLoader);

        // reload SPI with any new services from the plugin
        // 通过重新加载lucene的spi，来从插件中加载编解码器和分析器
        reloadLuceneSPI(loader);
        //获取当前线程的类加载器
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        try {
            // Set context class loader to plugin's class loader so that plugins
            // that have dependencies with their own SPI endpoints have a chance to load
            // and initialize them appropriately.
            // 将当前线程的上下文的类加载器设置与插件的类加载器一致，已确保与他们自己的spi端点具有依赖性的插件可以正确加载和初始化他们
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                Thread.currentThread().setContextClassLoader(loader);
                return null;
            });
            //加载plugin类对象
            Class<? extends Plugin> pluginClass = loadPluginClass(bundle.plugin.getClassname(), loader);
            //判断此类对象的加载器和当前插件的类加载器是否一致，从而来区分加载类对象的正确性
            if (loader != pluginClass.getClassLoader()) {
                throw new IllegalStateException("Plugin [" + name + "] must reference a class loader local Plugin class ["
                    + bundle.plugin.getClassname()
                    + "] (class loader [" + pluginClass.getClassLoader() + "])");
            }
            // 加载当前插件（通过反射来创建类对象对应的实例化对象）， 并将其添加到已加载插件的容器中
            Plugin plugin = loadPlugin(pluginClass, settings, configPath);
            loaded.put(name, plugin);
            return plugin;
        } finally {
            // 加载插件结束将上下文的类加载器设置回来
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                Thread.currentThread().setContextClassLoader(cl);
                return null;
            });
        }
    }

    /**
     * Reloads all Lucene SPI implementations using the new classloader.
     * 使用新的classloader来重新加载全部的lucene spi（服务调用接口 在meta-data目录下的service目录中）实现
     * This method must be called after the new classloader has been created to
     * register the services for use.
     * 必须调用此方法来创建新的类加载器来注册要使用的服务们
     */
    static void reloadLuceneSPI(ClassLoader loader) {
        // do NOT change the order of these method calls!
        // 不要更改下方方法的调用顺序

        // Codecs:
        // 编解码器：
        PostingsFormat.reloadPostingsFormats(loader);
        DocValuesFormat.reloadDocValuesFormats(loader);
        Codec.reloadCodecs(loader);
        // Analysis:
        //重新加载分析器（字符过滤器、分词器和过滤器）
        CharFilterFactory.reloadCharFilters(loader);
        TokenFilterFactory.reloadTokenFilters(loader);
        TokenizerFactory.reloadTokenizers(loader);
    }

    private Class<? extends Plugin> loadPluginClass(String className, ClassLoader loader) {
        try {
            return Class.forName(className, false, loader).asSubclass(Plugin.class);
        } catch (ClassNotFoundException e) {
            throw new ElasticsearchException("Could not find plugin class [" + className + "]", e);
        }
    }

    private Plugin loadPlugin(Class<? extends Plugin> pluginClass, Settings settings, Path configPath) {
        // 获取插件类对象的构造函数，并且在构造函数不唯一的时候抛出异常
        final Constructor<?>[] constructors = pluginClass.getConstructors();
        if (constructors.length == 0) {
            throw new IllegalStateException("no public constructor for [" + pluginClass.getName() + "]");
        }

        if (constructors.length > 1) {
            throw new IllegalStateException("no unique public constructor for [" + pluginClass.getName() + "]");
        }
        // 如果构造函数的参数大于两个，则异常终止
        final Constructor<?> constructor = constructors[0];
        if (constructor.getParameterCount() > 2) {
            throw new IllegalStateException(signatureMessage(pluginClass));
        }

        final Class[] parameterTypes = constructor.getParameterTypes();
        try {
            //通过反射使用其构造函数来创建插件类的实例化对象
            if (constructor.getParameterCount() == 2 && parameterTypes[0] == Settings.class && parameterTypes[1] == Path.class) {
                return (Plugin)constructor.newInstance(settings, configPath);
            } else if (constructor.getParameterCount() == 1 && parameterTypes[0] == Settings.class) {
                return (Plugin)constructor.newInstance(settings);
            } else if (constructor.getParameterCount() == 0) {
                return (Plugin)constructor.newInstance();
            } else {
                throw new IllegalStateException(signatureMessage(pluginClass));
            }
        } catch (final ReflectiveOperationException e) {
            throw new IllegalStateException("failed to load plugin class [" + pluginClass.getName() + "]", e);
        }
    }

    private String signatureMessage(final Class<? extends Plugin> clazz) {
        return String.format(
                Locale.ROOT,
                "no public constructor of correct signature for [%s]; must be [%s], [%s], or [%s]",
                clazz.getName(),
                "(org.elasticsearch.common.settings.Settings,java.nio.file.Path)",
                "(org.elasticsearch.common.settings.Settings)",
                "()");
    }

    public <T> List<T> filterPlugins(Class<T> type) {
        return plugins.stream().filter(x -> type.isAssignableFrom(x.v2().getClass()))
            .map(p -> ((T)p.v2())).collect(Collectors.toList());
    }
}
