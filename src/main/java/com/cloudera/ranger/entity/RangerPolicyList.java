package com.cloudera.ranger.entity;

import java.util.ArrayList;
import java.util.List;

import org.apache.ranger.plugin.model.RangerPolicy;

public class RangerPolicyList extends VList {
	private static final long serialVersionUID = 1L;

	List<RangerPolicy> policies = new ArrayList<RangerPolicy>();

	public RangerPolicyList() {
		super();
	}

	public RangerPolicyList(List<RangerPolicy> objList) {
		this.policies = objList;
	}

	public List<RangerPolicy> getPolicies() {
		return policies;
	}

	public void setPolicies(List<RangerPolicy> policies) {
		this.policies = policies;
	}


}
