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

package org.elasticsearch.cli;

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

import java.io.Closeable;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;

/**
 * An action to execute within a cli.
 * 在client中执行的操作
 */
public abstract class Command implements Closeable {

    /** A description of the command, used in the help output. */
    protected final String description;

    private final Runnable beforeMain;

    /** The option parser for this command. 创建此命令中的选项解析器，此解析器支持解析长命令的缩写 */
    protected final OptionParser parser = new OptionParser();

    private final OptionSpec<Void> helpOption = parser.acceptsAll(Arrays.asList("h", "help"), "Show help").forHelp();
    private final OptionSpec<Void> silentOption = parser.acceptsAll(Arrays.asList("s", "silent"), "Show minimal output");
    private final OptionSpec<Void> verboseOption =
        parser.acceptsAll(Arrays.asList("v", "verbose"), "Show verbose output").availableUnless(silentOption);

    /**
     * Construct the command with the specified command description and runnable to execute before main is invoked.
     *
     * @param description the command description
     * @param beforeMain the before-main runnable
     */
    public Command(final String description, final Runnable beforeMain) {
        this.description = description;
        this.beforeMain = beforeMain;
    }

    private Thread shutdownHookThread;

    /** Parses options for this command from args and executes it. */
    //从args中解析此命令中的选项并执行
    public final int main(String[] args, Terminal terminal) throws Exception {
        //是否安装shutdown钩子
        if (addShutdownHook()) {
            //设置在系统关闭时，钩子要执行的任务
            shutdownHookThread = new Thread(() -> {
                try {
                    //关闭当前命令行
                    this.close();
                } catch (final IOException e) {
                    //通过指定终端来输出对应错误信息
                    try (
                        StringWriter sw = new StringWriter();
                        PrintWriter pw = new PrintWriter(sw)) {
                        e.printStackTrace(pw);
                        terminal.errorPrintln(sw.toString());
                    } catch (final IOException impossible) {
                        // StringWriter#close declares a checked IOException from the Closeable interface but the Javadocs for StringWriter
                        // say that an exception here is impossible
                        throw new AssertionError(impossible);
                    }
                }
            });
            //将创建的关闭钩子方法添加到当前运行的上下文容器中
            Runtime.getRuntime().addShutdownHook(shutdownHookThread);
        }
        //执行需要在main方法执行之前的前置操作
        beforeMain.run();

        try {
            //通过启动main方法来执行给定的全部命令，如果遇到错误会全部抛出
            mainWithoutErrorHandling(args, terminal);
        } catch (OptionException e) {
            // print help to stderr on exceptions
            printHelp(terminal, true);
            terminal.errorPrintln(Terminal.Verbosity.SILENT, "ERROR: " + e.getMessage());
            return ExitCodes.USAGE;
        } catch (UserException e) {
            if (e.exitCode == ExitCodes.USAGE) {
                printHelp(terminal, true);
            }
            if (e.getMessage() != null) {
                terminal.errorPrintln(Terminal.Verbosity.SILENT, "ERROR: " + e.getMessage());
            }
            return e.exitCode;
        }
        return ExitCodes.OK;
    }

    /**
     * Executes the command, but all errors are thrown.
     * 解析当前给定的命令并执行，如果遇到错误会全部抛出
     */
    void mainWithoutErrorHandling(String[] args, Terminal terminal) throws Exception {
        //使用根据给定的选项规范创建的解析器来解析命令行中的参数
        final OptionSet options = parser.parse(args);

        //判断此次命令是否为help命令，如果是，则输出相关帮助信息，并且终止执行
        if (options.has(helpOption)) {
            printHelp(terminal, false);
            return;
        }
        //根据传给cli不同的参数来打印出不同的详细信息
        if (options.has(silentOption)) {
            terminal.setVerbosity(Terminal.Verbosity.SILENT);
        } else if (options.has(verboseOption)) {
            terminal.setVerbosity(Terminal.Verbosity.VERBOSE);
        } else {
            terminal.setVerbosity(Terminal.Verbosity.NORMAL);
        }
        //执行命令
        execute(terminal, options);
    }

    /** Prints a help message for the command to the terminal. */
    //将参数命令的帮助信息打印到终端上
    private void printHelp(Terminal terminal, boolean toStdError) throws IOException {
        if (toStdError) {
            terminal.errorPrintln(description);
            terminal.errorPrintln("");
            parser.printHelpOn(terminal.getErrorWriter());
        } else {
            terminal.println(description);
            terminal.println("");
            printAdditionalHelp(terminal);
            parser.printHelpOn(terminal.getWriter());
        }
    }

    /** Prints additional help information, specific to the command */
    protected void printAdditionalHelp(Terminal terminal) {}

    @SuppressForbidden(reason = "Allowed to exit explicitly from #main()")
    protected static void exit(int status) {
        System.exit(status);
    }

    /**
     * Executes this command.
     *
     * Any runtime user errors (like an input file that does not exist), should throw a {@link UserException}. */
    protected abstract void execute(Terminal terminal, OptionSet options) throws Exception;

    /**
     * Return whether or not to install the shutdown hook to cleanup resources on exit. This method should only be overridden in test
     * classes.
     * 是否安装shutdown钩子，以确保在系统关闭时来清除资源
     *
     * @return whether or not to install the shutdown hook
     */
    protected boolean addShutdownHook() {
        return true;
    }

    /** Gets the shutdown hook thread if it exists **/
    Thread getShutdownHookThread() {
        return shutdownHookThread;
    }

    @Override
    public void close() throws IOException {

    }

}
