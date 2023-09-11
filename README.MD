# 一、程序说明
## 1.1、功能说明
- 将Hive策略转换为HDFS策略（policy name带有rms-migrate/前缀）
- 消除不正确的Hive策略和输出（缺少表位置）
- 将重复的HDFS策略合并为一个（policy description带有merged policy关键字）
- 将HDFS策略导出为JSON文件(dfs-policy.json)
- 支持数据库和表级别的路径规则
- 生成权限检查脚本
- 批量导入策略到Ranger
## 1.2、性能说明
- 单线程运行
- 支持超大JSON文件，但不得超过1GB

# 二、如何使用
## 2.1、确保Ranger无策略增删改
1）停止集群（推荐）
```shell
// 1. 停止整个集群，确保不会有对Ranger的权限修改操作（包括Ranger Admin WebUI或Ranger Admin RestAPI）
CM > Action > Stop

// 2. 执行导入命令
shell> java -jar rms-migrate.jar ...

// 3. 启动其他组件
CM >  > Action > Start
```
2）仅停止Ranger服务
```shell
// 1. 停止Ranger服务（包括Ranger Admin、Ranger RMS、Ranger TagSync、Ranger UserSync）
CM > Ranger > Action > Stop

// 2. 执行导入命令
shell> java -jar rms-migrate.jar ...

// 3. 启动Ranger服务
CM > Ranger > Action > Start

```
3）确保Ranger处于ReadOnly（不推荐）
> 当前不会有任何服务、应用或API对Ranger执行策略的增删改操作，需要自行判断。

## 2.2、备份Ranger策略文件
### 2.2.1、导出Hive策略
1）导出Hive策略json文件
```shell
Ranger Admin WebUI > Home Page > Export button > Select Hive > Export button
```
> 上述操作完成后，会输出一个叫做Ranger_Policies_${yyyyMMdd_HHmmss}.json文件
### 2.2.2、导出HDFS策略
1）导出HDFS策略json文件
```shell
Ranger Admin WebUI > Home Page > Export button > Select HDFS > Export button
```
> 上述操作完成后，会输出一个叫做Ranger_Policies_${yyyyMMdd_HHmmss}.json文件
## 2.3、导出Hive元数据信息
1）生成表元数据文件
```sql
-- 将该SQL语句结果输出到文件中，以\t作为字段分隔符，删除第一行字段名称，同时确保没有空行
SELECT d.NAME,t.TBL_NAME,s.LOCATION FROM TBLS t LEFT JOIN SDS s ON(s.SD_ID=t.SD_ID) LEFT JOIN DBS d ON(d.DB_ID=t.DB_ID) WHERE d.NAME != "sys" AND d.NAME != "information_schema" AND s.LOCATION IS NOT NULL;
```
2）确认文件格式正确
- 先删除首行的列名
- 再删除空行
## 2.4、从Hive策略生成新的HDFS策略文件

1）主程序的参数说明

>- input_hive_policy_file_dir：ranger导出的hive策略文件（json格式），必选参数
>- input_hdfs_policy_file_dir：ranger导出的hdfs策略文件（json格式），必选参数
>- input_hive_table_info_file_dir：从mysql中查询出的表信息（包含db、table和location共3个字段，字段之间使用\t分割）
>- hdfs_service_name：ranger中hdfs服务的名称，必选参数
>- output_new_hdfs_policy_file_dir：生成新的hdfs策略文件（json格式）的存储位置，必选参数
>- generate_check_bash：是否生成check脚本，可选参数

2）运行命令如下

```shell
// Example 1
shell> java -jar rms-migrate.jar hive-policy.json hdfs-policy.json hivemeta.dat cm_hdfs /opt/rms-migrate
```
> 上述命令运行完成后，会在/opt/rms-migrate下生成一个叫做dfs-policy.json文件，这就是用于导入到Ranger的HDFS策略文件。
```shell
// Example 2
shell> java -jar rms-migrate.jar hive-policy.json hdfs-policy.json hivemeta.dat cm_hdfs /opt/rms-migrate y
```
> a. 上述命令运行完成后，会在/opt/rms-migrate下生成一个叫做dfs-policy.json文件，这就是用于导入到Ranger的HDFS策略文件。<br>
> b. 最后的y参数表示会在当前执行命令的目录下，生成一个叫做dfs-policy-check.sh的脚本文件。它不包含#!/bin/bash头，这需要我们根据实际用户来添加脚本头。需要注意的是，该脚本使用kinit命令的keytab文件位于/home/user/user.keytab。
## 2.5、导入新的HDFS策略文件到Ranger
1）策略文件导入
```shell
# 导入策略时，不允许应用对Ranger进行增删改操作，查询可以
Ranger Admin WebUI > Import button > Select Override Policy > Import button
```
> 等待时间约为：每1万条策略10分钟

2）如何验证导入成功
>+ 查询HDFS策略总条数，service：1表示hdfs，5表示hive<br/>
> SELECT COUNT(1)  FROM x_policy xp WHERE xp.service = 1;
>+ 查询迁移工具生成的策略条数<br/>
> SELECT COUNT(1) FROM x_policy xp WHERE xp.service = 1 AND name LIKE 'rms-migrate%';


# 三、如何停用RMS
> 此步骤停用了Ranger RMS, 可以完全规避由RMS导致的性能问题。停用RMS不会影响Hive和Impala, 但会影响到其他直连HDFS读写数据的计算引擎，如当某个跑批用户通过Spark直读Hive数据文件时，由于RMS停用，Ranger中如果没有对应的HDFS策略，那么该访问请求将被屏蔽。一般来说，需要检查可能被影响到的应用，根据实际情况添加对应的HDFS策略即可。您可以通过Ranger Admin UI或者REST API添加策略。以下是Ranger RMS的工作流程供参考:https://docs.cloudera.com/cdp-private-cloud-base/7.1.7/security-ranger-rms-configuring-and-using/topics/security-ranger-rms-configuring.html#pnavId2

## 3.1、关停Ranger RMS服务
```shell
CM > Ranger RMS > Action > Stop
```
## 3.2、删除主备NameNode本地的Mapping缓存
```shell
mv /var/lib/ranger/hdfs/policy-cache/hdfs_cm_hive_resource_mapping.json /tmp
```
## 3.3、删除以下配置（如果有）
```shell
CM > HDFS > Configuration => Safety Valve (ranger-hdfs-security.xml) 

Name : ranger.plugin.hdfs.chained.services
value : cm_hive

Name : ranger.plugin.hdfs.chained.services.cm_hive.impl
value : org.apache.ranger.chainedplugin.hdfs.hive.RangerHdfsHiveChainedPlugin

Name : ranger.plugin.hdfs.whitelisted.users
Value : testuser1
```
## 3.4、重启HDFS服务
```shell
CM > HDFS > Action > Restart
```