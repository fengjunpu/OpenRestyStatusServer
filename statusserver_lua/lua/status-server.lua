#!/usr/local/openresty/luajit/bin/luajit-2.1.0-alpha

-----------------代码规范说明-----------------
--[[
所有程序基本框架都是类似的
说明1>对错误应答的处理
	在processmsg函数中会调用各个处理分支，如果分支函数成功则其内部返回http应答
	如果返回失败，由processmsg判断返回值统一应答
说明2>对鉴权等常规共性的动作做好可以统一到脚本中去执行
说明3>HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
]]


--[设定搜索路径]
--将自定义包路径加入package的搜索路径中。也可以加到环境变量LUA_PATH中
--放到init_lus_path.lua中，不然的话，每一个请求处理的时候都会对全局变量
--package.path进行设置，导致

--[包含公共的模块]
local tableutils = require("common_lua.tableutils")		--打印工具
local myconfig = require("config_lua.myconfig")			--配置项
local script_utils = require("common_lua.script_utils")	--脚本工具
local cjson = require("cjson.safe")
local redis_iresty = require("common_lua.redis_iresty")
local wanip_iresty = require("common_lua.wanip_iresty")

--[基本变量参数]
--Redis服务器配置(会根据端口来进行修改)
local service_namespace = "dss"		--->默认
local auth_redis_ip="127.0.0.1"
local auth_redis_port=6437
local redis_ip="127.0.0.1"
local redis_port=6437

--发送应答数据报
function send_resp_table (status,resp)
	if not resp or type(resp) ~= "table" then
		ngx.log(ngx.ERR, "send_resp_table:type(resp) ~= table", type(resp))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
	--ngx.status = status
	local resp_str = cjson.encode(resp)
	--ngx.log(ngx.NOTICE, "send_resp_table:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end
function send_resp_string(status,message_type,error_string)
	if not message_type or type(message_type) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(message_type) ~= string", type(message_type))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	if not error_string or type(error_string) ~= "string" then
		ngx.log(ngx.ERR, "send_resp_string:type(error_string) ~= string", type(error_string))
		ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
	end
	--HTTP应答头统一都是OK，这样便于查找是应用错误，还是系统错误
	--ngx.status = status
	local jrsp = {}
	jrsp["StatusProtocol"] = {}
	jrsp["StatusProtocol"]["Header"] = {}
	jrsp["StatusProtocol"]["Header"]["Version"] = "1.0"
	jrsp["StatusProtocol"]["Header"]["CSeq"] = "1"
	jrsp["StatusProtocol"]["Header"]["MessageType"] = message_type
	jrsp["StatusProtocol"]["Header"]["ErrorNum"] = string.format("%d",status)
	jrsp["StatusProtocol"]["Header"]["ErrorString"] = error_string
	local resp_str = cjson.encode(jrsp)
	--ngx.log(ngx.NOTICE, "send_resp_string:", resp_str)
	ngx.header.content_length = string.len(resp_str)
	ngx.say(resp_str)
end

--对输入的参数做有效性检查，返回解码后的消息体对象json对象
function get_request_param()
	--ngx.log(ngx.NOTICE, "get_request_param:",ngx.var.request_body)
	local req_body, err = cjson.decode(ngx.var.request_body)
	if not req_body then
		ngx.log(ngx.ERR, "get_request_param:req body is not a json", ngx.var.request_body)
        return nil, "req body is not a json"
    end
	
    if not req_body["StatusProtocol"]
        or not req_body["StatusProtocol"]["Header"]
        or not req_body["StatusProtocol"]["Header"]["Version"]
        or not req_body["StatusProtocol"]["Header"]["CSeq"]
        or not req_body["StatusProtocol"]["Header"]["MessageType"]
	or not req_body["StatusProtocol"]["Body"]
      --  or not req_body["StatusProtocol"]["Body"]["SerialNumber"]
      --  or not req_body["StatusProtocol"]["Body"]["AuthCode"]
        or type(req_body["StatusProtocol"]["Header"]["Version"]) ~= "string"
	or type(req_body["StatusProtocol"]["Header"]["CSeq"]) ~= "string"
        or type(req_body["StatusProtocol"]["Header"]["MessageType"]) ~= "string"
        --or type(req_body["StatusProtocol"]["Body"]["SerialNumber"]) ~= "string"
        --or type(req_body["StatusProtocol"]["Body"]["AuthCode"]) ~= "string"
		then
        ngx.log(ngx.ERR, "invalid args")
        return nil, "invalid protocol format args"
    end
 
	return req_body, "success"
end

--查询设备的状态
function do_status_query(jreq)

	--判断Authccode的有效性(此处属性用"Read")
	local opt = {["redis_ip"]=auth_redis_ip,["redis_port"]=auth_redis_port,["timeout"]=3}
	local auth_red_handler = redis_iresty:new(opt)
	if not auth_red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new auth_red_handler failed")
		return false, "redis_iresty:new auth_red_handler failed"
	end
	--ngx.log(ngx.NOTICE, jreq["StatusProtocol"]["Body"]["SerialNumber"])
	--ngx.log(ngx.NOTICE, jreq["StatusProtocol"]["Body"]["AuthCode"])
	local ok, err = auth_red_handler:eval(script_utils.script_check_authcode,1,jreq["StatusProtocol"]["Body"]["SerialNumber"],jreq["StatusProtocol"]["Body"]["AuthCode"],"Read")
	if not ok then
	    ngx.log(ngx.ERR, "check authcode failed : ", err)
		return false,"check authcode failed"
	end

	--构造操作参数
	local key = jreq["StatusProtocol"]["Body"]["SerialNumber"]
	local args ={"TerminalType","VendorName","ServerIP","StreamStatus","StreamDssIP"}
	---这里没有区分dss专门处理，而是混在一起，是为了让下面接收的时候好处理一下
	---如果某一个字段查不到值，则status的数组中就没有这个项

	--操作具体的数据库
	local red_handler = redis_iresty:new({["redis_ip"]=redis_ip,["redis_port"]=redis_port,["timeout"]=3})
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new failed")
		return false,"redis_iresty:new failed"
	end

	red_handler:init_pipeline()
	for _, arg in ipairs(args) do
		red_handler:hget(key,arg)
	end
	local status,err = red_handler:commit_pipeline()

	--默认返回值
	local jrsp = {}
	jrsp["StatusProtocol"] = {}
	jrsp["StatusProtocol"]["Header"] = {}
	jrsp["StatusProtocol"]["Header"]["Version"] = "1.0"
	jrsp["StatusProtocol"]["Header"]["CSeq"] = "1"
	jrsp["StatusProtocol"]["Header"]["MessageType"] = "MSG_STATUS_QUERY_RSP"
	if not status or tableutils.table_is_empty(status) then
	    --ngx.log(ngx.ERR, "do_status_query:commit_pipeline failed", err)
		--没有查到
		jrsp["StatusProtocol"]["Header"]["ErrorNum"] = "404"
		jrsp["StatusProtocol"]["Header"]["ErrorString"] = "Not Found"
	else
		--tableutils.printTable(status)
		jrsp["StatusProtocol"]["Header"]["ErrorNum"] = "200"
		jrsp["StatusProtocol"]["Header"]["ErrorString"] = "Success OK"
		jrsp["StatusProtocol"]["Body"] = {}
		for i, value in pairs(status) do
			jrsp["StatusProtocol"]["Body"][args[i]] = value
		end
	end
	send_resp_table(ngx.HTTP_OK,jrsp)
	return true, "OK"
end

--批量查询设备状态
function do_status_mutliquery(jreq)

	--判断Authccode的有效性(此处属性用"Read")
	local opt = {["redis_ip"]=auth_redis_ip,["redis_port"]=auth_redis_port,["timeout"]=3}
	local auth_red_handler = redis_iresty:new(opt)
	if not auth_red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new auth_red_handler failed")
		return false, "redis_iresty:new auth_red_handler failed"
	end
	
	--逐个判断Authcode的有效性
	local authpass_array = {}
	local authnpass_array = {}
	if(type(jreq["StatusProtocol"]["Body"]["SerialNumber"]) == "string") then	
		local ok, err = auth_red_handler:eval(script_utils.script_check_authcode,1,jreq["StatusProtocol"]["Body"]["SerialNumber"],jreq["StatusProtocol"]["Body"]["AuthCode"],"Read")
		if not ok then
			ngx.log(ngx.ERR, "check authcode failed : ", err)
			authnpass_array[#authnpass_array+1] = jreq["StatusProtocol"]["Body"]["SerialNumber"]
		else
			authpass_array[#authpass_array+1] = jreq["StatusProtocol"]["Body"]["SerialNumber"]
		end
	else
		for index,value in ipairs(jreq["StatusProtocol"]["Body"]) do
			local ok, err = auth_red_handler:eval(script_utils.script_check_authcode,1,value.SerialNumber,value.AuthCode,"Read")
				if not ok then
					ngx.log(ngx.ERR, "check authcode failed : ", err)
					ngx.log(ngx.ERR,"the err authcode serialNumber :",index)
					authnpass_array[#authnpass_array+1] = value.SerialNumber
			else
					authpass_array[#authpass_array+1] = value.SerialNumber
				end
		end 
	end
	
	local red_handler = redis_iresty:new({["redis_ip"]=redis_ip,["redis_port"]=redis_port})
	if not red_handler then
	    ngx.log(ngx.ERR, "redis_iresty:new failed")
		return false,"redis_iresty:new failed"
	end
	
	--默认返回值
	local jrsp = {}
	jrsp["StatusProtocol"] = {}
	jrsp["StatusProtocol"]["Header"] = {}
	jrsp["StatusProtocol"]["Header"]["Version"] = "1.0"
	jrsp["StatusProtocol"]["Header"]["CSeq"] = "1"
	jrsp["StatusProtocol"]["Header"]["MessageType"] = "MSG_STATUS_MULTIQUERY_RSP"	
	
	local rspbody_array = {}
	local args ={"TerminalType","VendorName","ServerIP","StreamStatus","StreamDssIP"}
	--逐个查找在线状态
	for i,key in ipairs(authpass_array) do
		red_handler:init_pipeline()
		for _, arg in ipairs(args) do
			red_handler:hget(key,arg)
		end
		local status,err = red_handler:commit_pipeline() 
		if  not status or next(status)==nil then
			local off_arry = {}
			off_arry["SerialNumber"]=key
			off_arry["Status"]="Offline"
			rspbody_array[i] = off_arry
		else
			local on_arry = {}
			for n, value in pairs(status) do
				on_arry[args[n]] = value
			end
			on_arry["SerialNumber"] = key
			on_arry["Status"] = "Online"
			rspbody_array[i] = on_arry
		end
	end
	if next(authnpass_array) ~=nil then
		for x,key in pairs(authnpass_array) do
			local temp_arry = {}
			temp_arry["SerialNumber"] = key
			temp_arry["Status"] = "NotAllowed"
			rspbody_array[#rspbody_array + 1]=temp_arry
		end	
	end
	
	if next(rspbody_array) ~= nil then
		jrsp["StatusProtocol"]["Header"]["ErrorNum"] = "200"
		jrsp["StatusProtocol"]["Header"]["ErrorString"] = "Success OK"
		jrsp["StatusProtocol"]["Body"] = {}
		jrsp["StatusProtocol"]["Body"]= rspbody_array;
	end
	send_resp_table(ngx.HTTP_OK,jrsp)	
    return true, "OK"
end

--消息处理函数入库
function process_msg()

	--获取请求对象
	local jreq, err = get_request_param()
	if not jreq then
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any",err);
	    return
	end

	--分命令处理
	if(jreq["StatusProtocol"]["Header"]["MessageType"] == "MSG_STATUS_QUERY_REQ") then
		local ok, err = do_status_query(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_STATUS_QUERY_RSP",err);
		end
	elseif (jreq["StatusProtocol"]["Header"]["MessageType"] == "MSG_STATUS_MULTIQUERY_REQ") then
		local ok, err = do_status_mutliquery(jreq);
		if not ok then
			send_resp_string(ngx.HTTP_BAD_REQUEST,"MSG_STATUS_MULTIQUERY_RSP",err);
		end
	else
		ngx.log(ngx.ERR, "invalid MessageType",jreq["StatusProtocol"]["Header"]["MessageType"])
		send_resp_string(ngx.HTTP_BAD_REQUEST,"any","invalid MessageType");
	end
end

--加载对应的名字空间的IP地址的配置
local function load_dss_ip_addr()
	--<1>
	auth_redis_port = myconfig.myconfig_dss_redis4auth_port
	auth_redis_ip = ngx.shared.shared_data:get("myconfig_dss_redis4auth_ip")
	if not auth_redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_dss_redis4auth_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_dss_redis4auth_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_dss_redis4auth_ip", ip)
		auth_redis_ip = ip
	end
	--<2>
	redis_port = myconfig.myconfig_dss_redis4status_port	
	redis_ip = ngx.shared.shared_data:get("myconfig_dss_redis4status_ip")
	if not redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_dss_redis4status_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_dss_redis4status_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_dss_redis4status_ip", ip)
		redis_ip = ip
	end
	return true
end
local function load_tps_ip_addr()
	--<1>
	auth_redis_port = myconfig.myconfig_tps_redis4auth_port
	auth_redis_ip = ngx.shared.shared_data:get("myconfig_tps_redis4auth_ip")
	if not auth_redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_tps_redis4auth_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_tps_redis4auth_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_tps_redis4auth_ip", ip)
		auth_redis_ip = ip
	end
	--<2>
	redis_port = myconfig.myconfig_tps_redis4status_port	
	redis_ip = ngx.shared.shared_data:get("myconfig_tps_redis4status_ip")
	if not redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_tps_redis4status_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_tps_redis4status_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_tps_redis4status_ip", ip)
		redis_ip = ip
	end
	return true
end
local function load_p2p_ip_addr()
	--<1>
	auth_redis_port = myconfig.myconfig_p2p_redis4auth_port
	auth_redis_ip = ngx.shared.shared_data:get("myconfig_p2p_redis4auth_ip")
	if not auth_redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_p2p_redis4auth_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_p2p_redis4auth_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_p2p_redis4auth_ip", ip)
		auth_redis_ip = ip
	end
	--<2>
	redis_port = myconfig.myconfig_p2p_redis4status_port	
	redis_ip = ngx.shared.shared_data:get("myconfig_p2p_redis4status_ip")
	if not redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_p2p_redis4status_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_p2p_redis4status_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_p2p_redis4status_ip", ip)
		redis_ip = ip
	end
	return true
end
local function load_css_ip_addr()
	--<1>
	auth_redis_port = myconfig.myconfig_css_redis4auth_port
	auth_redis_ip = ngx.shared.shared_data:get("myconfig_css_redis4auth_ip")
	if not auth_redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_css_redis4auth_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_css_redis4auth_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_css_redis4auth_ip", ip)
		auth_redis_ip = ip
	end
	--<2>
	redis_port = myconfig.myconfig_css_redis4status_port	
	redis_ip = ngx.shared.shared_data:get("myconfig_css_redis4status_ip")
	if not redis_ip then
		local ip,err = wanip_iresty.getdomainip(myconfig.myconfig_css_redis4status_ip)
		if not ip then
			ngx.log(ngx.ERR,"getdomainip failed ",err,myconfig.myconfig_css_redis4status_ip)
			return false
		end
		ngx.shared.shared_data:set("myconfig_css_redis4status_ip", ip)
		redis_ip = ip
	end
	return true
end

--程序入口
--print("get request_body:"..ngx.var.request_body)
--print("get server_port::::",ngx.var.server_port,type(ngx.var.server_port))
if(ngx.var.server_port == "7701") then			-->status-dss.secu100.net:7701	-->dss-redis4status.secu100.net：5121
	service_namespace = "dss"
	local ok = load_dss_ip_addr()
	if not ok then
		ngx.log(ngx.ERR,"load_dss_ip_addr failed ")
		return false
	end
elseif (ngx.var.server_port == "7702") then	-->status-tps.secu100.net:7702	-->tps-redis4status.secu100.net：5122
	service_namespace = "tps"
	local ok = load_tps_ip_addr()
	if not ok then
		ngx.log(ngx.ERR,"load_dss_ip_addr failed ")
		return false
	end
elseif (ngx.var.server_port == "7703") then	-->status-p2p.secu100.net:7703	-->p2p-redis4status.secu100.net：5123
	service_namespace = "p2p"
	local ok = load_p2p_ip_addr()
	if not ok then
		ngx.log(ngx.ERR,"load_dss_ip_addr failed ")
		return false
	end
elseif (ngx.var.server_port == "7704") then	-->status-css.secu100.net:7704	-->css-redis4status.secu100.net：5125
	service_namespace = "css"
	local ok = load_css_ip_addr()
	if not ok then
		ngx.log(ngx.ERR,"load_dss_ip_addr failed ")
		return false
	end
else
	ngx.log(ngx.ERR,"invlaid ngx.var.server_port",ngx.var.server_port)
	return false
end
process_msg()

