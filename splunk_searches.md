### Heavy Forwarder traffic volume
```
index=_internal sourcetype=splunkd group=tcpin_connections (connectionType=cooked OR connectionType=cookedSSL) fwdType=full guid=* 
| eval dest_uri = host.":".destPort 
| stats values(fwdType) as forwarder_type, latest(version) as version, values(arch) as arch, dc(dest_uri) as dest_count, values(os) as os, max(_time) as last_connected, sum(kb) as new_sum_kb, sparkline(avg(tcp_KBps), 1m) as avg_tcp_kbps_sparkline, avg(tcp_KBps) as avg_tcp_kbps, avg(tcp_eps) as avg_tcp_eps by hostname 
```

```
index=_internal sourcetype=splunkd group=tcpin_connections (connectionType=cooked OR connectionType=cookedSSL) fwdType=full guid=*
| eval gb = kb/1024/1024
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(_time) AS time
| stats latest(version) as version, values(os) as os, max(time) as last_connected, sum(gb) as "Traffic(GB)", sparkline(avg(tcp_KBps), 1m) as avg_tcp_kbps_spark, avg(tcp_KBps) as avg_tcp_kbps, avg(tcp_eps) as avg_tcp_eps by hostname
| addcoltotals "Traffic(GB)"
```

### Forwarders connecting directly to indexer, both UF and HF
```
index=_internal source=*metrics.log group=tcpin_connections 
    [ search index=_internal splunk_server=* earliest=-5m 
    | dedup splunk_server 
    | eval host=splunk_server 
    | fields host 
    | format] 
| stats values(os) as os values(version) as version values(hostname) as hostname values(guid) as guid values(fwdType) as fwdType values(ssl) as ssl values(connectionType) as connectionType by sourceIp
```

### Fowarders connection
```
index=_internal  group=tcp*_connections   sourcetype=splunkd 
| eval temp=split(lastIndexer,":") | eval forwardedtoport=mvindex(temp,1)
| eval LastTime=strftime(_time, "%c") 
| eventstats dc(group) as GROUP  by host
| eval isIF=if(GROUP==2,"yes","no")
| eval ingest_pipe=if(isnull(ingest_pipe),"1",ingest_pipe)
| stats  max(LastTime) as LastTime  values(lastIndexer) as "Forwared To"  values(host) as "Receiving Host" values(forwardedtoport) as "Receiving Port" values(connectionType) as "Conn Type" values(ssl) as "SSL Enabled"  values(fwdType) as fwdType values(isIF) as "Receiving Host is IF"  max(tcp_KBps) as "max tcp_KBps by Receiving Host"  by hostname ingest_pipe
| appendcols [search index=_internal group=per_source_thruput series=*splunkd.log 
| stats max(kbps) as maxkbps avg(kbps) as avgkbps-fwd perc25(kbps) as perc25kbps-fwd median(kbps) as mediamkbps-fwd perc75(kbps) as perc75kbps-fwd perc90(kbps) as pertc90kbps-fwd by host | rename host as hostname]
| foreach *kbps* [eval <<FIELD>>=round('<<FIELD>>', 5)]
| search hostname=SOMEHOST
```

### Data routing by cluster
```
index=_internal  group=tcpout_connections  tcp_KBps>0 host= <<HF_SERVER>>
| rex field=name "(?<tcp_group>[\w\-]+):(?<dst_ip>\d+.\d+.\d+.\d+:\d+):\d+"
| timechart span=1m avg(tcp_KBps) by tcp_group
```

###  Hourly License Usage by pool
```
index=_internal host=<<LM_SERVER>>* source=*license_usage.log* type=Usage 
| eval GB = round(b/1024/1024/1024,5) 
| eval platform=pool
| timechart usenull=f span=1h sum(GB) as GB by pool
| addtotals
```

### connection to indexers
```
index=_internal source=*metrics.log* group=tcpin_connections host=<INDEXERS>
| dedup hostname destPort 
| table _time hostname version fwdType ack os sourceIp destPort ssl 
| sort version
```

### indexing distribution
```
index=_internal host=gen-idx* sourcetype=splunkd source=*metrics.log component=Metrics group=queue 
| eval fill_perc = round(current_size_kb / max_size_kb * 100) 
| eval agg_fill_perc = case(match(name, "aggqueue"), fill_perc) 
| eval parsing_fill_perc = case(match(name, "parsingqueue*"), fill_perc) 
| eval index_fill_perc = case(match(name, "indexqueue*"), fill_perc) 
| eval typing_fill_perc = case(match(name, "typingqueue*"), fill_perc) 
| timechart span=5m perc90(index_fill_perc) by host useother=f
```

### blocked output
```
index=_internal sourcetype = splunkd host=* source=*splunkd.log blocked seconds 
| rex field=_raw "Forwarding to output group (?<output_group>\S+)\shas been blocked for (?<block_seconds>\d+)\sseconds" 
| where block_seconds > 300
| eval cluster = case(output_group == "splunkssl", "AWS", output_group LIKE "%luster%2", "Cluster02", output_group == "default-autolb-group", "Cluster01", output_group LIKE "%luster%1", "Cluster01")
| table _time host cluster block_seconds
```

### missing indexes events
```
| rest /services/messages 
| table title message severity timeCreated_iso published server splunk_server author
| rex field=message "So far received events from (?<missing_indexes>\d+) missing"
| where missing_indexes > 0
```

### search performance
```
index=_audit (host="<<Search_Head>>) action=search (id=* OR search_id=*) search_id!="'subsearch*" search_id!="*scheduler*" info=completed 
| eval search_id=if(isnull(search_id), id, search_id) 
| replace '*' with * in search_id 
| search search_id!=rt_* search_id!=searchparsetmp* 
| rex "search='(?<search>.*?)', autojoin" 
| rex "savedsearch_name=\"(?<savedsearch_name>.*?)\"\]\[" 
| eval search=case(isnotnull(search),search,isnull(search) AND savedsearch_name!="","Scheduled search name : ".savedsearch_name,isnull(search) AND savedsearch_name=="","SID : ".search_id) 
| eval user = if(user="n/a", "nobody", user) 
| search search_id=* search!=typeahead* search!="|history*" search!=*_internal* search!=*_audit* 
| dedup search_id 
| timechart span=1m avg(total_run_time)
```

### cold voume usage
```
index=_introspection (host=<<INDEXERS>>*) component=Partitions 
| spath output=capacity path=data.capacity 
| spath output=available path=data.available 
| eval utilised=100-(available/capacity*100) 
| search *cold 
| timechart span=1m max(utilised) as utilised_max p95(utilised) as utilised_p95 avg(utilised) as utilised_avg limit=100 by host
```

### clients connected to DS
```
| rest splunk_server=<<DS>> /services/deployment/server/clients 
| fields ip,clientName,hostname,instanceName,name,guid
```


### indexer performance 
```
https://<<SPLUNK>>/en-US/app/cluster_health_tools/indexer_performance?form.time.earliest=-3100s%40s&form.time.latest=now&form.refresh_rate_seconds=999999&form.show_table=| noop&form.show_debug=| noop&form.introspection=index%3D_introspection&form.internal=index%3D_internal&form.selected_field=avg_average_kbps&form.split_by=splunk_version&form.selected_bins=250&form.bubble_selected_field_x=avg_instantaneous_kbps&form.bubble_selected_field_y=avg_search_concurrency&form.bubble_selected_field_size=avg_normalized_load_avg_1min&form.bubble_split_by=site_id&form.bar_kpi=avg_normalized_load_avg_1min&form.bar_aggregation_function=count&form.bar_split_by=splunk_version 
```

### searching keyword in saved searches
```
| rest splunk_server=local /servicesNS/-/-/saved/searches
| search search="*<<KEYWORD>>*"
| table title, author, eai:acl.app search
```

### checking data time range
```
| tstats count earliest(_time) as first_accessed, latest(_time) as last_accessed where index=_introspection 
| eval days=round((last_accessed-first_accessed)/3600/24,1)
| eval last_accessed=strftime(last_accessed,"%+"), first_accessed=strftime(first_accessed,"%+")
```

### cpu util by search group
```
index=_introspection host=<<IDX>> component=PerProcess "data.search_props.provenance"=scheduler
| rex field=data.search_props.label "^_?(?<groups>[^_\s\.]+)"
| timechart usenull=f span=1h avg(data.normalized_pct_cpu) by groups limit=100
```

### DMA usage on ES
```
| rest splunk_server=local /services/saved/searches 
| where match('action.correlationsearch.enabled', "1") 
| where match('disabled', "0") 
| rename eai:acl.app as app, title as csearch_name, action.correlationsearch.label as csearch_label, action.notable.param.security_domain as security_domain 
| fields csearch_name, csearch_label, app, security_domain, cron_schedule, search
| rex field=search "datamodel\s*=[^\w\*]*(?<dm_name>[\w]+)"
| stats values(csearch_name) by dm_name
```

### check lookup files not in use for x number of days
```
| rest splunk_server=local servicesNS/-/-/data/lookup-table-files 
| search eai:appName !=TA-* AND eai:appName !=Splunk_TA_* 
| eval filename = title 
| rename eai:appName as app, eai:acl.sharing as permission, eai:data as file, eai:userName as user, title as lookup_name 
| eval jField=filename.app 
| fields lookup_name filename jField app user file 
| append 
    [| rest splunk_server=local servicesNS/-/-/data/transforms/lookups 
    | rename title as lookup_name eai:acl.app as app 
    | search type=file AND app !=TA-* AND app !=Splunk_TA_* 
    | fields lookup_name filename app 
    | eval jField = filename.app
        ] 
| append 
    [| rest splunk_server=local services/search/distributed/bundle-replication-files 
    | explorebundle 
    | eval exFiletype = if( in(filetype,"py","pyc","conf","tsidx","pre-tsidx","pyo","meta","README","key","val"),0,1) 
    | search exFiletype = 1 
    | rename file as filename 
    | eval jField = filename.app 
    | fields sizeMB jField filetype ] 
| stats values(lookup_name) as lookup_name values(app) as app values(filename) as filename values(sizeMB) as sizeMB values(filetype) as filetype values(user) as user values(file) as file by jField 
| fields - jField 
| append 
    [ search index=_audit (host=<<SHC_MEMBER>>) action=search TERM(lookup) 
    | rex max_match=10 field=search "\|\s*(lookup|inputlookup)\b\s*(?<lookup_name>[a-zA-Z0-9_\\.\-\(\):]+)\b" 
    | stats count as usedlookupCount by lookup_name
        ] 
| stats values(file) as file values(sizeMB) as sizeMB values(app) as app values(filetype) as filetype values(usedlookupCount) as usedlookupCount values(user) as user values(filename) as filename by lookup_name 
| fillnull value=0 file usedlookupCount 
| eventstats sum(usedlookupCount) as UC by filename 
| search UC < 1 
| eventstats sum(sizeMB) as TotalUnusedSize
```

### check index attributes
```
| rest splunk_server=<<IDX_SERVER>> /services/data/indexes
| where disabled = 0
| search title IN (<<INDEX_NAME>> )
| eval currentDBSizeGB = round( currentDBSizeMB / 1024)
| eval max_index_size_gb=round(maxTotalDataSizeMB/1024)
| eval retenion=round(frozenTimePeriodInSecs/24/60/60)
| eval epoch_max_time=strptime(maxTime, "%Y-%m-%dT%H:%M:%S"), epoch_min_time=strptime(minTime, "%Y-%m-%dT%H:%M:%S")
| eval data_range=round((epoch_max_time-epoch_min_time)/24/60/60)
| fields title summaryHomePath_expanded minTime maxTime data_range retenion  currentDBSizeGB  max_index_size_gb homePath coldPath
| rename minTime AS earliest maxTime AS latest summaryHomePath_expanded AS index_path currentDBSizeGB AS index_size_gb coldToFrozenDir AS index_path_frozen title AS index
```

### savedsearch skewer
```
| rest splunk_server=local /servicesNS/-/-/saved/searches
    search="is_scheduled=1" search="disabled=0" 
| fields search title author cron_schedule eai:acl.app eai:acl.sharing dispatch.earliest_time dispatch.latest_time action.summary_index search id 
| search NOT (dispatch.earliest_time=rt* OR dispatch.latest_time=rt* OR action.summary_index=1 OR search=*timechart* OR search=bin OR search=span OR search=*bucket*) 
| eval cron_type=case
    (match(cron_schedule,"\*/5 \* \* \* \*"),5,
    match(cron_schedule,"\*/10 \* \* \* \*"),10,
    match(cron_schedule,"\*/15 \* \* \* \*"),15,
    match(cron_schedule,"\*/30 \* \* \* \*"),30,
    match(cron_schedule,"^0 \* \* \* \*"),0,0=0,-1) 
| where cron_type >= 0 
| sort cron_type 
| eval reset_count=case(cron_type=5,4,
    cron_type=10,9,
    cron_type=15,14,
    cron_type=30,29,
    cron_type=0,59
    ) 
| streamstats count reset_after="count=reset_count" by cron_type 
| eval lower_bound=count 
| eval upper_bound=59 
| eval new_cron=case
    (
    cron_type=0,count . " * * * *",
    cron_type!=0,lower_bound . "-" . upper_bound . "/" . cron_type . " * * * *"
    ) 
| eval change_script="curl -k -u admin:password -XPOST " + id + " -d " + "cron_schedule=\"" + new_cron + "\" || true" 
| eval rollback_script="curl -k -u admin:password -XPOST " + id + " -d " + "cron_schedule=\"" + cron_schedule + "\" || true" 
| fields title author cron_schedule new_cron eai:acl.app eai:acl.sharing change_script rollback_script
```
