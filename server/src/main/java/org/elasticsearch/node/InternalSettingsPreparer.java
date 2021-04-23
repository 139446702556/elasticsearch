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

package org.elasticsearch.node;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.function.Function;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsException;
import org.elasticsearch.env.Environment;
import org.elasticsearch.node.Node;

public class InternalSettingsPreparer {

    private static final String SECRET_PROMPT_VALUE = "${prompt.secret}";
    private static final String TEXT_PROMPT_VALUE = "${prompt.text}";

    /**
     * Prepares settings for the transport client by gathering all
     * elasticsearch system properties and setting defaults.
     */
    public static Settings prepareSettings(Settings input) {
        Settings.Builder output = Settings.builder();
        initializeSettings(output, input, Collections.emptyMap());
        finalizeSettings(output, () -> null);
        return output.build();
    }

    /**
     * Prepares the settings by gathering all elasticsearch system properties, optionally loading the configuration settings.
     * 通过收集elasticsearch的全部系统属性来准备设置，可以选择加载配置设置
     * @param input      the custom settings to use; these are not overwritten by settings in the configuration file
     * @param properties map of properties key/value pairs (usually from the command-line)
     * @param configPath path to config directory; (use null to indicate the default)
     * @param defaultNodeName supplier for the default node.name if the setting isn't defined
     * @return the {@link Environment}
     */
    public static Environment prepareEnvironment(Settings input, Map<String, String> properties,
            Path configPath, Supplier<String> defaultNodeName) {
        // just create enough settings to build the environment, to get the config dir
        //创建设置构造器对象
        Settings.Builder output = Settings.builder();
        //初始化构造器对象（将已经存在的配置添加整合到构造器对象中，并对其中的占位符进行解析替换）
        initializeSettings(output, input, properties);
        //通过当前的全部设置（系统属性、环境变量和命令行）来创建环境的实例化变量
        Environment environment = new Environment(output.build(), configPath);
        //es 5.5.0版本以上的服务统一使用yml文件进行配置，禁止使用yaml和json文件，在此检测存在则抛出异常
        if (Files.exists(environment.configFile().resolve("elasticsearch.yaml"))) {
            throw new SettingsException("elasticsearch.yaml was deprecated in 5.5.0 and must be renamed to elasticsearch.yml");
        }

        if (Files.exists(environment.configFile().resolve("elasticsearch.json"))) {
            throw new SettingsException("elasticsearch.json was deprecated in 5.5.0 and must be converted to elasticsearch.yml");
        }
        //创建一个新的设置构建器,用来存储服务的配置文件的内容
        output = Settings.builder(); // start with a fresh output
        //获取服务的配置文件elasticsearch.yml的路径
        Path path = environment.configFile().resolve("elasticsearch.yml");
        //加载服务配置文件的内容到output对象中
        if (Files.exists(path)) {
            try {
                output.loadFromPath(path);
            } catch (IOException e) {
                throw new SettingsException("Failed to load settings from " + path.toString(), e);
            }
        }

        // re-initialize settings now that the config file has been loaded
        //配置文件的设置已经加载，重新进行初始化settings
        initializeSettings(output, input, properties);
        //检查设置，以确保其中不存在旧的设置方式
        checkSettingsForTerminalDeprecation(output);
        //进行设置的最终初始化
        finalizeSettings(output, defaultNodeName);
        //通过全部配置创建Environment对象，并返回
        return new Environment(output.build(), configPath);
    }

    /**
     * Initializes the builder with the given input settings, and applies settings from the specified map (these settings typically come
     * from the command line).
     * 使用给定的输入设置来初始化Settings对象的构造器，并对其中的占位符进行解析替换
     *
     * @param output the settings builder to apply the input and default settings to
     * @param input the input settings
     * @param esSettings a map from which to apply settings
     */
    static void initializeSettings(final Settings.Builder output, final Settings input, final Map<String, String> esSettings) {
        output.put(input);
        output.putProperties(esSettings, Function.identity());
        output.replacePropertyPlaceholders();
    }

    /**
     * Checks all settings values to make sure they do not have the old prompt settings. These were deprecated in 6.0.0.
     * This check should be removed in 8.0.0.
     * 检查配置，以确保其中没有旧的设置方式
     */
    private static void checkSettingsForTerminalDeprecation(final Settings.Builder output) throws SettingsException {
        // This method to be removed in 8.0.0, as it was deprecated in 6.0 and removed in 7.0
        assert Version.CURRENT.major != 8: "Logic pertaining to config driven prompting should be removed";
        for (String setting : output.keys()) {
            final String value = output.get(setting);
            if (value != null) {
                switch (value) {
                    case SECRET_PROMPT_VALUE:
                        throw new SettingsException("Config driven secret prompting was deprecated in 6.0.0. Use the keystore" +
                            " for secure settings.");
                    case TEXT_PROMPT_VALUE:
                        throw new SettingsException("Config driven text prompting was deprecated in 6.0.0. Use the keystore" +
                            " for secure settings.");
                }
            }
        }
    }

    /**
     * Finish preparing settings by replacing forced settings and any defaults that need to be added.
     * 通过替换强制设置以及需要添加的任何默认设置来完成设置准备工作
     */
    private static void finalizeSettings(Settings.Builder output, Supplier<String> defaultNodeName) {
        // allow to force set properties based on configuration of the settings provided
        //从当前全部设置中查找出全部强制设置
        List<String> forcedSettings = new ArrayList<>();
        for (String setting : output.keys()) {
            if (setting.startsWith("force.")) {
                forcedSettings.add(setting);
            }
        }
        //将全部的强制设置的key进行重新命名（去掉开头的force.）
        for (String forcedSetting : forcedSettings) {
            String value = output.remove(forcedSetting);
            output.put(forcedSetting.substring("force.".length()), value);
        }
        //解析并替换掉设置中的占位符
        output.replacePropertyPlaceholders();

        // put the cluster and node name if they aren't set
        //设置集群名称，默认为elasticsearch（集群名称不能为，不能包含冒号）
        if (output.get(ClusterName.CLUSTER_NAME_SETTING.getKey()) == null) {
            output.put(ClusterName.CLUSTER_NAME_SETTING.getKey(), ClusterName.CLUSTER_NAME_SETTING.getDefault(Settings.EMPTY).value());
        }
        //设置节点名称，默认为当前系统的hostname值
        if (output.get(Node.NODE_NAME_SETTING.getKey()) == null) {
            output.put(Node.NODE_NAME_SETTING.getKey(), defaultNodeName.get());
        }
    }
}
