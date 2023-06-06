package com.cloudera.ranger.entity;

import java.util.LinkedHashMap;
import java.util.Map;

public class RangerExportPolicyList extends RangerPolicyList implements java.io.Serializable {
	private static final long serialVersionUID = 1L;
	
	Map<String, Object> metaDataInfo = new LinkedHashMap<String, Object>();

	public Map<String, Object> getMetaDataInfo() {
		return metaDataInfo;
	}

	public void setMetaDataInfo(Map<String, Object> metaDataInfo) {
		this.metaDataInfo = metaDataInfo;
	}

}