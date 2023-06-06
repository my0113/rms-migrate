package com.cloudera.ranger.entity;

import java.io.Serializable;

/**
 * @Description TODO
 * @Created by mengyao
 * @Date 2023/5/31 10:58
 * @Version 1.0
 */
public class MetadataInfo implements Serializable {

    private String db;
    private String table;
    private boolean isDbLevel;
    private String location;

    public MetadataInfo() {
    }

    public MetadataInfo(String db, String table, String location) {
        this.db = db;
        this.table = table;
        this.location = location;
    }

    public MetadataInfo(String db, String table, boolean isDbLevel, String location) {
        this.db = db;
        this.table = table;
        this.isDbLevel = isDbLevel;
        this.location = location;
    }

    public String getDb() {
        return db;
    }

    public void setDb(String db) {
        this.db = db;
    }

    public String getTable() {
        return table;
    }

    public void setTable(String table) {
        this.table = table;
    }

    public boolean isDbLevel() {
        return isDbLevel;
    }

    public void setDbLevel(boolean dbLevel) {
        isDbLevel = dbLevel;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    @Override
    public String toString() {
        return "MetadataInfo{" +
                "db='" + db + '\'' +
                ", table='" + table + '\'' +
                ", isDbLevel=" + isDbLevel +
                ", location='" + location + '\'' +
                '}';
    }

}
