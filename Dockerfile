#Dockerfile
FROM daocloud.io/geyijun/open_resty_common:v0.03
MAINTAINER geyijun<geyijun@xiongmaitech.com>

sudo yum -y install bind-utils
sudo yum -y install jq

#²ÉÓÃsupervisorÀ´¹ÜÀí¶àÈÎÎñ
COPY supervisord.conf /etc/supervisord.conf
COPY statusserver_lua/ /xm_workspace/xmcloud3.0/statusserver_lua/

EXPOSE 7701 7702 7703 7704
CMD ["supervisord"]
 
