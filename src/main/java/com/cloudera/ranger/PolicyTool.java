package com.cloudera.ranger;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import com.cloudera.ranger.entity.MetadataInfo;
import com.cloudera.ranger.entity.RangerExportPolicyList;
import com.google.common.collect.Lists;
import org.apache.ranger.authorization.hadoop.constants.RangerHadoopConstants;
import org.apache.ranger.plugin.model.RangerPolicy;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Objects.*;
import static org.apache.commons.lang.StringUtils.*;
import static org.apache.commons.io.FileUtils.*;

/**
 * 1、Conversion Hive Policies to HDFS Policies
 * 2、Eliminate incorrect Hive policies and output(Missing table location)
 * 3、Merge duplicate HDFS policies into one(keyword: description=merged policy)
 * 4、Export HDFS policies as a JSON file(dfs-policy.json)
 * 5、Support path rules at the database and table levels(Single table and single database)
 * 6、Generate permission check script
 * @Description TODO
 * @Created by mengyao
 * @Date 2023/5/23 13:35
 * @Version 1.0
 */
public class PolicyTool {

    /** Commons **/
    private static final String ENCODING = "UTF-8";
    private static final String FIX_SEPARATOR = "/";
    private static final String MERGE_SEPARATOR = " - ";
    private static final String ANY = "*";
    private static final Pattern HDFS_DOMAIN_PATTERN = Pattern.compile("^hdfs?://[^/]+");
    /** Hive policy resource key **/
    private static final String RANGER_HIVE_SERVICE_TYPE = "hive";
    private static final String HIVE_POLICY_DATABASE = "database";
    private static final String HIVE_POLICY_TABLE = "table";
    private static final String HIVE_POLICY_COLUMN = "column";
    /** HDFS policy resource key **/
    private static final String RANGER_HDFS_SERVICE_TYPE = "hdfs";
    private static final String HDFS_POLICY_PATH = "path";
    private static final String HDFS_POLICY_NAME = "dfs-policy.json";
    private static final String HDFS_POLICY_PREFIX = "rms-migrate";
    private static final String HDFS_POLICY_BASH = "dfs-policy-check.sh";

    static {
        JSON.config(JSONWriter.Feature.LargeObject);
    }

    /** Full hive policy permissions **/
    private static final List<RangerPolicy.RangerPolicyItemAccess> hivePrivileges = Arrays.asList(
        new RangerPolicy.RangerPolicyItemAccess("select"),
        new RangerPolicy.RangerPolicyItemAccess("update"),
        new RangerPolicy.RangerPolicyItemAccess("create"),
        new RangerPolicy.RangerPolicyItemAccess("drop"),
        new RangerPolicy.RangerPolicyItemAccess("alter"),
        new RangerPolicy.RangerPolicyItemAccess("index"),
        new RangerPolicy.RangerPolicyItemAccess("lock"),
        new RangerPolicy.RangerPolicyItemAccess("all"),
        new RangerPolicy.RangerPolicyItemAccess("read"),
        new RangerPolicy.RangerPolicyItemAccess("write"),
        new RangerPolicy.RangerPolicyItemAccess("repladmin"),
        new RangerPolicy.RangerPolicyItemAccess("serviceadmin"),
        new RangerPolicy.RangerPolicyItemAccess("tempudfadmin"),
        new RangerPolicy.RangerPolicyItemAccess("refresh"),
        /**
         * 参考：https://docs.cloudera.com/runtime/7.2.15/security-ranger-authorization/topics/security-ranger-resource-policy-storage-handler.html
         * 定义：StorageHandler
         * 示例：storage-uri:
         *     phoenix-cluster:port/table-name
         *     bootstrap-server:port/kafka-topic
         *     mysql-host:port/DBname/*
         */
        new RangerPolicy.RangerPolicyItemAccess("rwstorage")
    );
    /** Full hdfs policy permissions **/
    private static final List<RangerPolicy.RangerPolicyItemAccess> hdfsPrivileges = Arrays.asList(
        new RangerPolicy.RangerPolicyItemAccess(RangerHadoopConstants.READ_ACCCESS_TYPE, true),
        new RangerPolicy.RangerPolicyItemAccess(RangerHadoopConstants.WRITE_ACCCESS_TYPE, true),
        new RangerPolicy.RangerPolicyItemAccess(RangerHadoopConstants.EXECUTE_ACCCESS_TYPE, true)
    );

    public static void main(String[] args) {
        if (args.length<4) {
            System.err.println("Usage: <input_hive_policy_file_dir> <input_hdfs_policy_file_dir> <input_hive_table_info_file_dir> <hdfs_service_name> <output_new_hdfs_policy_file_dir> [generate_check_bash]");
            System.exit(1);
        }
        // ranger hive policy json file directory
        String hivePolicyFileDir = args[0];
        // ranger hdfs policy json file directory
        String hdfsPolicyFileDir = args[1];
        // hive warehouse directory
        String tableInfoFileDir = args[2];
        // ranger hdfs service name
        String hdfsServiceName = args[3];
        // new ranger hdfs policy name
        String newHdfsPolicyFileDir = args[4];
        // check permission hdfs path
        boolean dfsPermCheck = args.length == 6 && nonNull(args[5]);

        // loading hive policies json
        List<RangerPolicy> hivePolicies = importPolicies(hivePolicyFileDir);
        // loading hdfs policies json
        List<RangerPolicy> hdfsPolicies = importPolicies(hdfsPolicyFileDir);
        // loading hive db or table metastore
        Map<String, MetadataInfo> metadataInfo = loadMetadataInfo(tableInfoFileDir);

        // hive policies conversion to hdfs policies
        RangerExportPolicyList hdfsPolicyList = hiveToHdfs(hivePolicies, hdfsPolicies, metadataInfo, true, hdfsServiceName);
        // export hdfs policies to local directory
        exportPoliciesToJson(hdfsPolicyList, newHdfsPolicyFileDir);

        // generate check bash file
        if (dfsPermCheck) {
            dfsPermCheck(newHdfsPolicyFileDir.concat(HDFS_POLICY_NAME));
        }
    }

    /**
     * Load policies from local json files
     * @param policiesFile
     * @return
     */
    private static List<RangerPolicy> importPolicies(String policiesFile) {
        List<RangerPolicy> policiesList = null;
        String jsonStr = null;
        String policiesStr = null;
        try {
            jsonStr = readFileToString(new File(policiesFile), ENCODING);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }
        System.out.println(">>>> File "+policiesFile+" loaded.");
        JSONObject jsonObj = JSON.parseObject(jsonStr);
        if (!jsonObj.isEmpty()) {
            policiesStr = jsonObj.getString("policies");
        }
        if (isNotEmpty(policiesStr)) {
             policiesList = JSON.parseArray(policiesStr, RangerPolicy.class);
        }
        System.out.println(">>>> File "+policiesFile+" parsed.");
        return policiesList;
    }

    /**
     * Convert the hive policy to the hdfs policy
     * @param hivePolicies
     * @param metadataInfo
     * @param policyIsEnable
     * @param serviceName
     * @return
     */
    private static RangerExportPolicyList hiveToHdfs(List<RangerPolicy> hivePolicies, List<RangerPolicy> hdfsPolicies, Map<String, MetadataInfo> metadataInfo, boolean policyIsEnable, String serviceName) {
        RangerExportPolicyList rangerExportPolicyList = new RangerExportPolicyList();
        // 无效策略，即非db/table类型的资源
        List<RangerPolicy> invalidPolicies = new ArrayList<>();
        System.out.println("hive policy's conversion to hdfs policy's beginning.");
        for (RangerPolicy policy : hivePolicies) {
            String serviceType = policy.getServiceType();
            String rawName = policy.getName();
            if (isEmpty(serviceType)) {
                System.err.println("policy("+ rawName +") is not hive type.");
                continue;
            }
            // build hdfs path
            if (policyIsEnable && serviceType.equalsIgnoreCase(RANGER_HIVE_SERVICE_TYPE)) {
                Map<String, RangerPolicy.RangerPolicyResource> hivePolicyResources = policy.getResources();
                String db = null;
                String tbl = null;
                String col = null;
                String dbOrTableInfoKey = null;
                if (hivePolicyResources.containsKey(HIVE_POLICY_DATABASE)) {
                    RangerPolicy.RangerPolicyResource hivePolicyResource = hivePolicyResources.get(HIVE_POLICY_DATABASE);
                    List<String> dbs = hivePolicyResource.getValues();
                    if (null != dbs && dbs.size() > 0) {
                        db = dbs.get(0);
                    }
                }
                if (hivePolicyResources.containsKey(HIVE_POLICY_TABLE)) {
                    RangerPolicy.RangerPolicyResource hivePolicyResource = hivePolicyResources.get(HIVE_POLICY_TABLE);
                    List<String> tbls = hivePolicyResource.getValues();
                    if (null != tbls && tbls.size() > 0) {
                        tbl = tbls.get(0);
                    }
                }
                if (hivePolicyResources.containsKey(HIVE_POLICY_COLUMN)) {
                    RangerPolicy.RangerPolicyResource hivePolicyResource = hivePolicyResources.get(HIVE_POLICY_COLUMN);
                    List<String> cols = hivePolicyResource.getValues();
                    if (null != cols && cols.size() > 0) {
                        col = cols.get(0);
                    }
                }
                /**
                 * 当db或table为null表示非db/table类型的资源，等同于以下条件
                 * if (hivePolicyResources.containsKey("storage-type")||hivePolicyResources.containsKey("storage-url")) {
                 *     continue;
                 * }
                 * if (hivePolicyResources.containsKey("global")) {
                 *     continue;
                 * }
                 * if (hivePolicyResources.containsKey("url")) {
                 *     continue;
                 * }
                 */
                if (isEmpty(db)||isEmpty(tbl)) {
                    System.err.println("The current policy is of type "+hivePolicyResources+", not of type db/table");
                    invalidPolicies.add(policy);
                    continue;
                }
                // 当db不为null或为*，且table不为null或为*时，权限类型为db/table，值为*/*或db/*
                if ((isNotEmpty(db)||db.equals(ANY))&&(isNotEmpty(tbl)||tbl.equals(ANY))) {
                    dbOrTableInfoKey = String.join(FIX_SEPARATOR, db, tbl);
                }
                // 0. get metadata(db or table) info
                final MetadataInfo metaInfo = metadataInfo.get(dbOrTableInfoKey);
                if (isNull(metaInfo)) {
                    // 表示db/table在hive元数据中不存在，一般是对table或db执行了drop动作
                    System.err.println("Unable to find metadata based on "+dbOrTableInfoKey);
                    invalidPolicies.add(policy);
                    continue;
                }
                // 1. update hive policy to hdfs policy
                policy.setId(0L);
                policy.setGuid(null);
                policy.setServiceType(RANGER_HDFS_SERVICE_TYPE);
                policy.setVersion(1L);
                policy.setService(serviceName);
                policy.setPolicyType(RangerPolicy.POLICY_TYPE_ACCESS);
                policy.setName(String.join(FIX_SEPARATOR, HDFS_POLICY_PREFIX, rawName));
                // 2. Cleaner policy old resources <databases> and <tables> and <columns>
                policy.getResources().clear();
                policy.setResourceSignature(null);
                // 3. Setting policy new resources <path>
                policy.getResources().put(HDFS_POLICY_PATH, new RangerPolicy.RangerPolicyResource() {{
                    setValue(metaInfo.getLocation());
                    setIsExcludes(false);
                    setIsRecursive(true);
                }});
                // 4. Setting access permissions
                // 4.1 allow conditions
                conversion(policy.getPolicyItems());
                // 4.2 allow conditions
                conversion(policy.getAllowExceptions());
                // 4.3 deny conditions
                conversion(policy.getDenyPolicyItems());
                // 4.4 deny conditions
                conversion(policy.getDenyExceptions());
            }
        }
        if (hivePolicies.size()>0) {
            // 5. Delete invalid policies
            if (invalidPolicies.size()>0) {
                hivePolicies.removeAll(invalidPolicies);
            }
            // 6. Merge old hdfs policies to the new policies(var:hivePolicies)
            if (nonNull(hdfsPolicies)) {
                hivePolicies.addAll(hdfsPolicies);
            }
            // 7.1 Find duplicate policies
            Map<String, List<RangerPolicy>> duplicatePoliciesMap = new HashMap<>();
            hivePolicies.forEach(policy -> {
                String path = policy.getResources().get(HDFS_POLICY_PATH).getValues().get(0).trim();
                if (!duplicatePoliciesMap.containsKey(path)) {
                    duplicatePoliciesMap.put(path, Lists.newArrayList(policy));
                } else {
                    duplicatePoliciesMap.get(path).add(policy);
                }
            });
            // 7.2 Merge duplicate policies
            List<RangerPolicy> distinctPolicies = duplicatePoliciesMap.values()
                    .stream()
                    .filter(vals -> vals.size() > 1)
                    .map(PolicyTool::mergeDupHdfsPolicies)
                    .collect(Collectors.toList());
            // 7.3 Update full policies
            if (duplicatePoliciesMap.size()>0 && distinctPolicies.size()>0) {
                List<RangerPolicy> duplicatePoliciesList = duplicatePoliciesMap.values()
                        .stream()
                        .filter(vals -> vals.size() > 1)
                        .flatMap(Collection::stream)
                        .collect(Collectors.toList());
                hivePolicies.removeAll(duplicatePoliciesList);
                hivePolicies.addAll(distinctPolicies);
            }
            rangerExportPolicyList.setPolicies(hivePolicies);
        }
        System.out.println("hive policy's conversion to hdfs policy's finished.");
        return rangerExportPolicyList;
    }

    /**
     * Hive and hdfs access mappings
     * @param accessType
     * @return
     */
    private static List<RangerPolicy.RangerPolicyItemAccess> hiveToHdfsPermissionMapping(String accessType) {
        List<RangerPolicy.RangerPolicyItemAccess> dfsAccesses = null;
        if (accessType.matches("(?i)all|repladmin|serviceadmin|tempudfadmin|rwstorage")) {
            dfsAccesses = hdfsPrivileges;
        }
        if (accessType.matches("(?i)select|read|refresh")) {
            dfsAccesses = Arrays.asList(hdfsPrivileges.get(0), hdfsPrivileges.get(2));
        }
        if (accessType.matches("(?i)update|create|drop|alter|write|index|lock")) {
            dfsAccesses = Arrays.asList(hdfsPrivileges.get(1), hdfsPrivileges.get(2));
        }
        return dfsAccesses;
    }

    /**
     * Conversion hive access to hdfs access
     * @param policies
     */
    private static void conversion(List<RangerPolicy.RangerPolicyItem> policies) {
        if (nonNull(policies)) {
            policies.forEach(policyItem -> {
                List<RangerPolicy.RangerPolicyItemAccess> rawAccesses = policyItem.getAccesses();
                Map<String, RangerPolicy.RangerPolicyItemAccess> newAccesses = null;
                if (nonNull(rawAccesses)) {
                    newAccesses = new HashMap<>();
                    for (RangerPolicy.RangerPolicyItemAccess access : rawAccesses) {
                        // Get raw permission(hive permission)
                        String accessType = access.getType();
                        // Conversion hive permission to hdfs permission
                        List<RangerPolicy.RangerPolicyItemAccess> dfsPermission = hiveToHdfsPermissionMapping(accessType);
                        if (nonNull(dfsPermission)&&dfsPermission.size()>0) {
                            for (RangerPolicy.RangerPolicyItemAccess dfsPerm : dfsPermission) {
                                String dfsPermType = dfsPerm.getType();
                                if (!newAccesses.containsKey(dfsPermType)) {
                                    newAccesses.put(dfsPermType, dfsPerm);
                                }
                            }
                        }
                    }
                }
                policyItem.getAccesses().clear();
                if (nonNull(newAccesses)&&newAccesses.size()>0) {
                    policyItem.getAccesses().addAll(newAccesses.values());
                }
            });
        }
    }

    /**
     * Merge duplicate policies(hdfs policy resource key: path)
     * @param duplicatePolicies
     * @return
     */
    private static RangerPolicy mergeDupHdfsPolicies(List<RangerPolicy> duplicatePolicies) {
        if (nonNull(duplicatePolicies)) {
            RangerPolicy fp = duplicatePolicies.get(0);
            duplicatePolicies.stream().filter(p -> p.hashCode()!=fp.hashCode()).forEach(p -> {
                /** setName **/
                fp.setName(String.join(MERGE_SEPARATOR, fp.getName(), p.getName()));
                // fp.setService(p.getService());
                // fp.setPolicyType(p.getPolicyType());
                // fp.setPolicyPriority(p.getPolicyPriority());
                /** setDescription **/
                fp.setDescription(String.join(MERGE_SEPARATOR, fp.getDescription(), p.getDescription(), "merged policy"));
                // fp.setResourceSignature(p.getResourceSignature());
                // fp.setIsAuditEnabled(p.getIsAuditEnabled());
                /** setResources **/
                if (nonNull(fp.getResources())&&nonNull(p.getResources())) {
                    fp.getResources().merge(HDFS_POLICY_PATH, p.getResources().get(HDFS_POLICY_PATH), (o1, o2) -> o1.equals(o2) ? o1 : o2);
                }
                if (isNull(fp.getResources())&&nonNull(p.getResources())) {
                    fp.setResources(p.getResources());
                }
                /** setPolicyItems **/
                if (nonNull(fp.getPolicyItems())&&nonNull(p.getPolicyItems())) {
                    fp.setPolicyItems(Stream.concat(fp.getPolicyItems().stream(), p.getPolicyItems().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getPolicyItems())&&nonNull(p.getPolicyItems())) {
                    fp.setPolicyItems(p.getPolicyItems());
                }
                /** setDenyPolicyItems **/
                if (nonNull(fp.getDenyPolicyItems())&&nonNull(p.getDenyPolicyItems())) {
                    fp.setDenyPolicyItems(Stream.concat(fp.getDenyPolicyItems().stream(), p.getDenyPolicyItems().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getDenyPolicyItems())&&nonNull(p.getDenyPolicyItems())) {
                    fp.setDenyPolicyItems(p.getDenyPolicyItems());
                }
                /** setAllowExceptions **/
                if (nonNull(fp.getAllowExceptions())&&nonNull(p.getAllowExceptions())) {
                    fp.setAllowExceptions(Stream.concat(fp.getAllowExceptions().stream(), p.getAllowExceptions().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getAllowExceptions())&&nonNull(p.getAllowExceptions())) {
                    fp.setAllowExceptions(p.getAllowExceptions());
                }
                /** setDenyExceptions **/
                if (nonNull(fp.getDenyExceptions())&&nonNull(p.getDenyExceptions())) {
                    fp.setDenyExceptions(Stream.concat(fp.getDenyExceptions().stream(), p.getDenyExceptions().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getDenyExceptions())&&nonNull(p.getDenyExceptions())) {
                    fp.setDenyExceptions(p.getDenyExceptions());
                }
                /** setDataMaskPolicyItems **/
                if (nonNull(fp.getDataMaskPolicyItems())&&nonNull(p.getDataMaskPolicyItems())) {
                    fp.setDataMaskPolicyItems(Stream.concat(fp.getDataMaskPolicyItems().stream(), p.getDataMaskPolicyItems().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getDenyExceptions())&&nonNull(p.getDenyExceptions())) {
                    fp.setDataMaskPolicyItems(p.getDataMaskPolicyItems());
                }
                /** setRowFilterPolicyItems **/
                if (nonNull(fp.getRowFilterPolicyItems())&&nonNull(p.getRowFilterPolicyItems())) {
                    fp.setRowFilterPolicyItems(Stream.concat(fp.getRowFilterPolicyItems().stream(), p.getRowFilterPolicyItems().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getRowFilterPolicyItems())&&nonNull(p.getRowFilterPolicyItems())) {
                    fp.setRowFilterPolicyItems(fp.getRowFilterPolicyItems());
                }
                // fp.getOptions();
                /** getValiditySchedules **/
                if (nonNull(fp.getValiditySchedules())&&nonNull(p.getValiditySchedules())){
                    fp.setValiditySchedules(Stream.concat(fp.getValiditySchedules().stream(), p.getValiditySchedules().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getValiditySchedules())&&nonNull(p.getValiditySchedules())){
                    fp.setValiditySchedules(p.getValiditySchedules());
                }
                /** getPolicyLabels **/
                if (nonNull(fp.getPolicyLabels())&&nonNull(p.getPolicyLabels())) {
                    fp.setPolicyLabels(Stream.concat(fp.getPolicyLabels().stream(), p.getPolicyLabels().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getPolicyLabels())&&nonNull(p.getPolicyLabels())) {
                    fp.setPolicyLabels(p.getPolicyLabels());
                }
                // fp.setZoneName(p.getZoneName());
                /** getConditions **/
                if (nonNull(fp.getConditions())&&nonNull(p.getConditions())) {
                    fp.setConditions(Stream.concat(fp.getConditions().stream(), p.getConditions().stream()).collect(Collectors.toList()));
                }
                if (isNull(fp.getConditions())&&nonNull(p.getConditions())) {
                    fp.setConditions(p.getConditions());
                }
            });
            return fp;
        }
        return null;
    }

    /**
     * Export the policies as a local json file
     * @param policyList
     * @param hdfsPolicyFileDir
     */
    private static void exportPoliciesToJson(RangerExportPolicyList policyList, String hdfsPolicyFileDir) {
        String jsonStr = JSON.toJSONString(policyList);
        try {
            String path = String.join(FIX_SEPARATOR, hdfsPolicyFileDir, HDFS_POLICY_NAME);
            write(new File(path), jsonStr, ENCODING);
            System.out.println(">>>> New HDFS Policy File "+path+" generate successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从SQL输出的文件中获取表级别的location，也包含db级别的location
     * SQL语句:
     *     SELECT d.NAME,t.TBL_NAME,s.LOCATION FROM TBLS t LEFT JOIN SDS s ON(s.SD_ID=t.SD_ID) LEFT JOIN DBS d ON(d.DB_ID=t.DB_ID) WHERE d.NAME != "sys" AND d.NAME != "information_schema" AND s.LOCATION IS NOT NULL;
     * @param tableFileDir
     * @return
     */
    private static Map<String, MetadataInfo> loadMetadataInfo(String tableFileDir) {
        Map<String, MetadataInfo> tableInfo = new HashMap<>();
        try {
            List<String> lines = readLines(new File(tableFileDir), ENCODING);
            System.out.println(">>>> File "+tableFileDir+" loaded.");
            if (lines.size()>0) {
                lines.forEach(line -> {
                    String[] fields = line.split("\t");
                    if (fields.length == 3) {
                        String db = fields[0];
                        String table = fields[1];
                        String location = fields[2];
                        String dfsDomain = extractDomain(location);
                        if (isNotEmpty(dfsDomain)) {
                            location = location.substring(dfsDomain.length());
                        }
                        // 1. add table level location
                        tableInfo.put(String.join(FIX_SEPARATOR, db, table), new MetadataInfo(db, table, location));
                        // 2. add db level location
                        String dbInfoKey = String.join(FIX_SEPARATOR, db, ANY);
                        if (!tableInfo.containsKey(dbInfoKey)) {
                            tableInfo.put(dbInfoKey, new MetadataInfo(db, ANY, location.substring(0, location.length() - table.length() - 1)));
                        }
                    }
                });
                // 3. add */* location
                tableInfo.put(String.join(FIX_SEPARATOR, ANY, ANY), new MetadataInfo(ANY, ANY, true, ANY));
                System.out.println(">>>> File "+tableFileDir+" parsed.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return tableInfo;
    }

    /**
     * Match path string hdfs://nameservice and hdfs://hostname:port
     * @param path
     * @return
     */
    private static String extractDomain(String path) {
        Matcher matcher = HDFS_DOMAIN_PATTERN.matcher(path);
        if (matcher.find()){
            return matcher.group();
        }
        return null;
    }

    /**
     * Generate a script file that checks hdfs path permissions
     * @param dfsPolicyFileDir
     */
    private static void dfsPermCheck(String dfsPolicyFileDir) {
        final String CMD_PREFIX = "hdfs dfs ";
        List<RangerPolicy> policies = importPolicies(dfsPolicyFileDir);
        Map<String, List<String>> userCmds = new HashMap<>();
        policies.stream().filter(p -> nonNull(p.getResources()) && p.getResources().containsKey(HDFS_POLICY_PATH))
                .forEach(p -> {
                    RangerPolicy.RangerPolicyResource res = p.getResources().get(HDFS_POLICY_PATH);
                    String path = res.getValues().get(0);
                    if (nonNull(path) && !path.contains("*")) {
                        p.getPolicyItems().forEach(pi -> {
                            List<String> users = pi.getUsers();
                            if (nonNull(users)) {
                                List<String> cmds = new ArrayList<>();
                                List<RangerPolicy.RangerPolicyItemAccess> accesses = pi.getAccesses();
                                accesses.forEach(a -> {
                                    if (a.getType().equalsIgnoreCase(RangerHadoopConstants.READ_ACCCESS_TYPE)) {
                                        cmds.add(CMD_PREFIX+"-cat ".concat(path));
                                    }
                                    if (a.getType().equalsIgnoreCase(RangerHadoopConstants.WRITE_ACCCESS_TYPE)) {
                                        cmds.add(CMD_PREFIX+"-touch ".concat(path).concat(FIX_SEPARATOR+"rms-migrate-test"));
                                        cmds.add(CMD_PREFIX+"-rm -r ".concat(path).concat(FIX_SEPARATOR+"rms-migrate-test"));
                                    }
                                    if (a.getType().equalsIgnoreCase(RangerHadoopConstants.EXECUTE_ACCCESS_TYPE)) {
                                        cmds.add(CMD_PREFIX+"-ls ".concat(path));
                                    }
                                });
                                users.forEach(user -> {
                                    userCmds.put(user, cmds);
                                });
                            }
                        });
                    }
                });
        List<String> fullCmds = new LinkedList<>();
        userCmds.forEach((user,cmds) -> {
            if (cmds.size()>0) {
                fullCmds.add("su - ".concat(user));
                // Assume that the keytab files are all in the user's home directory
                fullCmds.add("kinit -kt ".concat(user).concat(".keytab ").concat(user));
                fullCmds.add("exit");
                fullCmds.addAll(cmds);
            }
        });
        if (fullCmds.size() > 0) {
            try {
                File file = new File(HDFS_POLICY_BASH);
                writeLines(file, fullCmds);
                System.out.println(">>>> HDFS Path Permission Check File "+file.getAbsolutePath()+" generate successfully.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

}
