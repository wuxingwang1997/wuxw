#!/bin/bash
#set -e

cat <<EOF
+--------------------------------+
|                                |
| centos system initialization...|
|                                |
+--------------------------------+
EOF

[ ! -f /usr/bin/wget ] && yum install -y wget
cat /etc/issue | grep -q "6\." && osversion="6" || osversion="7"

function expect_install {
[ ! -f /usr/bin/expect ] && yum -y install expect || return 0
}

COLORGROUP="/etc/profile.d/colorgroup.sh"
CRON_CONF_DIR="/var/spool/cron/root"



function user {
mkdir /bin/whole51/
echo qwe123.com | passwd --stdin root
groupadd admin
useradd admin -g admin
echo admin##1 | passwd --stdin admin
sed -i "s/#Port 22/Port 58958/g" /etc/ssh/sshd_config
#sed -i '$iAllowUsers chengyangyang' /etc/ssh/sshd_config
service sshd restart
grep -q chengyangyang /etc/sudoers|| echo "admin  ALL=(ALL)  NOPASSWD: ALL" >> /etc/sudoers

}

function system_change {

for i in \
git \
gcc \
gcc-c++ \
autoconf \
libjpeg \
pcre \
pcre-devel \
libevent \
libevent-devel \
libjpeg-devel \
libpng \
libpng-devel \
freetype \
freetype-devel \
libxml2 \
libxml2-devel \
zlib \
zlib-devel \
glibc \
glibc-devel \
glib2 \
glib2-devel \
bzip2 \
bzip2-devel \
ncurses \
ncurses-devel \
curl \
curl-devel \
lvm2 \
e2fsprogs \
e2fsprogs-devel \
krb5-devel \
libidn \
libidn-devel \
;
do
yum -y install  $i 
[ $? -ne 0 ] && exit 1
done

echo "yum 更新最新源"
yum update -y

echo "关闭selinux"
getenforce  | grep -q Disabled || sed -i '/^SELINUX/s#.*#SELINUX=disabled#g' /etc/selinux/config

echo “修改系统相关内核参数”
if grep -q 'export HISTTIMEFORMAT="%F %T `whoami` "' /etc/profile
then
return 0
else
echo 'net.ipv4.ip_forward = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_ignore_bogus_error_responses = 0
net.ipv4.tcp_mem = 78643200 104857600 157286400
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_keepalive_time = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_sack = 0
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_rmem = 4096 65536 524288
net.ipv4.tcp_wmem = 32768
net.core.wmem_max = 1048576
net.core.rmem_max = 16777216
net.core.rmem_max = 16777216
net.core.rmem_default = 16777216
net.core.netdev_max_backlog = 262144
net.ipv4.ip_local_port_range = 5000 65000
kernel.printk_ratelimit_burst = 0
kernel.printk_ratelimit = 0
kernel.printk = 6417
kernel.msgmni = 1024
kernel.sem = 250 256000 32 1024
fs.file-max = 655350
vm.overcommit_memory = 1
vm.swappiness = 0
net.ipv4.tcp_mtu_probing = 1
fs.inotify.max_user_watches = 50000000
net.nf_conntrack_max = 25000000
net.netfilter.nf_conntrack_max = 25000000
net.netfilter.nf_conntrack_tcp_timeout_established = 180
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
fs.inotify.max_queued_events = 327679' >/etc/sysctl.conf
sysctl -p
#修改history

echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >>/etc/profile

#修改系统时区

ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
echo 'ZONE="Asia/Shanghai"' >/etc/sysconfig/clock

###同步时间

touch $CRON_CONF_DIR
chmod 600 $CRON_CONF_DIR
if grep -q "ntpdate" $CRON_CONF_DIR ; then
 echo "ERR ntpdate exist"
else
 echo "0 */1 * * * /usr/sbin/ntpdate 192.168.1.220;/sbin/hwclock -w && hwclock --systohc >/dev/null 2>&1 "  >>$CRON_CONF_DIR
 echo "00 * * * * /usr/sbin/ntpdate ntp.org >/dev/null 2>&1" >>$CRON_CONF_DIR

[ $? -ne 0 ] && exit 1
fi

#install colorgroup

if [ ! -f $COLORGROUP ];then
   touch "$COLORGROUP"
echo "# color-grep initialization" >>$COLORGROUP
echo "/usr/libexec/grepconf.sh -c || return" >>$COLORGROUP
echo "alias grep='grep --color=auto' 2>/dev/null" >>$COLORGROUP
echo "alias egrep='egrep --color=auto' 2>/dev/null" >>$COLORGROUP
echo "alias fgrep='fgrep --color=auto' 2>/dev/null" >>$COLORGROUP
source /etc/profile
fi

echo "修改limit参数"

echo "admin soft nproc 20240" >>/etc/security/limits.conf
echo "admin hard nproc 65536" >>/etc/security/limits.conf
grep -q 65535 /etc/security/limits.conf || echo "* - nofile 65535" >>/etc/security/limits.conf

#锁定关键文件系统

#chattr +i /etc/passwd
#chattr +i /etc/inittab
#chattr +i /etc/group
#chattr +i /etc/shadow
#chattr +i /etc/gshadow

#对所有用户设置自动注销功能 300表示自动注销的时间为300秒。

touch /etc/proflie.d/logoff.sh
echo "TMOUT=300" >/etc/proflie.d/logoff.sh
echo "export TOMOUT" >>/etc/proflie.d/logoff.sh

#reset locaDNS

sed -i '1inameserver 172.16.2.204' /etc/resolv.conf
sed -i '2inameserver 172.16.2.205' /etc/resolv.conf

fi
}

function jdk {
PKG_NAME="http://172.16.2.187/jdk"
curl -O $PKG_NAME/jdk-8u144-linux-x64.gz

if [ -f jdk-8u144-linux-x64.gz ];then
    tar -xf   jdk-8u144-linux-x64.gz -C /usr/local/ 1>/dev/null
    else
    echo "File java.tar.gz does not exist, please check"
 exit
fi

touch /etc/profile.d/java.sh

echo  "export JAVA_HOME=/usr/local/jdk1.8.0_144" >/etc/profile.d/java.sh
echo  "export CLASSPATH=.:\$JAVA_HOME/jre/lib/rt.jar:\$JAVA_HOME/lib/dt.jar:\$JAVA_HOME/lib/tools.jar" >>/etc/profile.d/java.sh
echo  "export PATH=$PATH:\$JAVA_HOME/bin" >>/etc/profile.d/java.sh
source /etc/profile

###test java
java -version

rm -rf jdk-8u144-linux-x64.gz
which java >/dev/null 2>&1


if [ "$?" == "0" ];then
echo "========JAVA install succeed========"
exit
fi
echo "========JAVA install failure========"
exit
 }

function epel_repo {
rpm -qa | grep -q epel && return 0
echo "配置安装epel源"
rpm -qa | grep -q epel || rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-${osversion}.noarch.rpm
}

function nginx_repo {
[ -f /etc/yum.repos.d/nginx ] && return 0
echo "配置安装nginx源"
rpm -qa | grep -q nginx && yum remove nginx -y
rpm -qa | grep -q nginx || rpm -ivh http://nginx.org/packages/centos/${osversion}/noarch/RPMS/nginx-release-centos-${osversion}-0.el${osversion}.ngx.noarch.rpm
}

function yum_soft {
php --version | grep -q 5.4.38 && return 0
echo "卸载系统自带php,httpd"
yum remove -y php* httpd
echo "安装相关软件"
for i in \
bison \
bison-devel \
readline \
readline-devel \
openssl-devel \
libmcrypt.x86_64 \
libmcrypt-devel.x86_64 \
cyrus-sasl-devel.x86_64 \
php \
httpd \
httpd-devel \
nginx \
;
do
yum -y install  $i 
[ $? -ne 0 ] && exit 1
done

chkconfig nginx on

}

function yum_php_m {
php -m | grep -q mongo && return 0
echo "安装php相关扩展"

for i in \
php-mysql \
php-gd \
php-devel \
php-eaccelerator \
php-pear \
php-mbstring \
php-mcrypt \
php-mhash \
php-xml \
php-imap \
php-ldap \
php-soap \
php-xmlrpc \
php-memcache \
;
do
[ $? -ne 0 ] && exit 1
done
yum install -y $1

echo “安装mongo扩展”


/usr/bin/expect << EOF
    set timeout 30
    sleep 2
    spawn pecl install mongo
    sleep 2
    expect "MongoDB Enterprise Authentication"
    sleep 2
    send "\r"
    expect "extension=mongo.so\" to php.ini"
    sleep 2
    expect "."

EOF

echo "extension=mongo.so" >/etc/php.d/mongo.ini

echo "安装redis扩展"

pecl install redis

echo "extension=redis.so">/etc/php.d/redis.ini

echo "安装yac扩展"
pecl install yac-0.9.2

echo "extension=yac.so" >>/etc/php.d/yac.ini
echo "yac.keys_memory_size=128M" >>/etc/php.d/yac.ini
#修改php相关参数
sed  -i 's/^;date.timezone =/date.timezone = Asia\/Shanghai/' /etc/php.ini
sed -ri '/post_max_size/c\post_max_size = 30M'  /etc/php.ini
sed -ri '/upload_max_filesize/c\upload_max_filesize = 30M'  /etc/php.ini
sed -ri '/memory_limit/c\memory_limit = 1024M' /etc/php.ini
sed -ri '/expose_php/c\expose_php = Off' /etc/php.ini
sed -ri '/^session.cookie_httponly/c\session.cookie_httponly = 1' /etc/php.ini

echo '[eaccelerator]
zend_extension = "/usr/lib64/php/modules/eaccelerator.so"
eaccelerator.shm_size="128"
eaccelerator.cache_dir="/var/cache/eaccelerator"
eaccelerator.enable="1"
eaccelerator.optimizer="1"
eaccelerator.check_mtime="1"
eaccelerator.debug="0"
eaccelerator.filter=""
eaccelerator.shm_max="0"
eaccelerator.shm_ttl="0"
eaccelerator.shm_prune_period="0"
eaccelerator.shm_only="0"
eaccelerator.compress="1"
eaccelerator.compress_level="9" ' >/etc/php.d/eaccelerator.ini
mkdir -p /var/cache/eaccelerator
chmod 777 /var/cache/eaccelerator
}

function httpd_soft {
grep -Pq "MaxRequestsPerChild    4000" /etc/httpd/conf/httpd.conf && return 0
perl -i -pe 's#LogFormat "\%h \%l \%u \%t \\"\%r\\" \%\>s %b" common#LogFormat "\%{X-Forwarded-For}i \%h \%D \%u \%t \\"\%r\\" \%\>s \%b" common#g' /etc/httpd/conf/httpd.conf

sed -ri '/ServerTokens/c\ServerTokens ProductOnly' /etc/httpd/conf/httpd.conf
sed -ri '/ServerSignature/c\ServerSignature Off'   /etc/httpd/conf/httpd.conf
sed -ri '/^#ServerName/c\ServerName  localhost'    /etc/httpd/conf/httpd.conf

sed -ri '/^Listen/d' /etc/httpd/conf/httpd.conf
sed -ri '/ServerLimit/d' /etc/httpd/conf/httpd.conf
sed -ri '/IfModule prefork.c/ a\ServerLimit      2560' /etc/httpd/conf/httpd.conf
sed -ri '/^StartServers/c\StartServers    16'  /etc/httpd/conf/httpd.conf
sed -ri '/^MinSpareServers/c\MinSpareServers    10'  /etc/httpd/conf/httpd.conf
sed -ri '/^MaxSpareServers/c\MaxSpareServers    30'  /etc/httpd/conf/httpd.conf
sed -ri '/^MaxClients/c\MaxClients    2560'  /etc/httpd/conf/httpd.conf
sed -ri '/^MaxRequestsPerChild/c\MaxRequestsPerChild    4000' /etc/httpd/conf/httpd.conf

echo "TraceEnable off" >>/etc/httpd/conf/httpd.conf

chkconfig httpd on
}

function bcmath {
php -m | grep -q bcmath && return 0
echo "安装php bcmath扩展"
wget http://jp2.php.net/get/php-5.4.38.tar.gz/from/this/mirror

tar zxf mirror

cd php-5.4.38/ext/bcmath

/usr/bin/phpize

./configure --with-php-config=/usr/bin/php-config

make && make install

echo "extension=bcmath.so" >/etc/php.d/bcmath.ini

}


function mysql_soft {
#安装mysql    
rpm -qa | grep -q MySQL-server && { echo mysql is already installed;return 0; }
yum remove mysql* -y
yum install -y MySQL-server-5.6.20 MySQL-client MySQL-embedded MySQL-devel

chkconfig mysql on
}

function zabbix_agent {
rpm -qa | grep -q zabbix && return 0

rpm -ivh http://mirrors.aliyun.com/zabbix/zabbix/3.4/rhel/7/x86_64/zabbix-agent-3.4.9-1.el7.x86_64.rpm

echo "修改zabbix配置文件"

hostname=` hostname`
IP=`hostname -I`
echo "PidFile=/var/run/zabbix/zabbix_agentd.pid
LogFile=/var/log/zabbix/zabbix_agentd.log
LogFileSize=0
Server=172.16.2.187
ServerActive=172.16.2.187
Hostname=$IP-$hostname
Timeout=10
UnsafeUserParameters=1
HostMetadata=7daiserver" >/etc/zabbix/zabbix_agentd.conf
systemctl enable zabbix-agent.service
service zabbix-agent restart


[ $? -ne 0  ] && echo "zabbix client fails to start, check the manual"&& exit
echo "zabbix agent service starts successfully !!! "

#See iptables  & listening port
ps -aux | grep zabbix
netstat -ntulp | grep 10050
iptables -nvL

#Add boot service
[ $? -eq 0  ] &&  echo  "Add boot service OK！！！"
cat << a
+---------------------------------------------------------+
|          zabbix_agentd  Install   Successful            |
+---------------------------------------------------------+
a
}

function disk_mount {

mkdir /data
pvcreate /dev/vdb
vgcreate vdb-vg /dev/vdb
lvcreate -l 100%FREE -n vdb-lv vdb-vg
mkfs.ext4 /dev/mapper/vdb--vg-vdb--lv
tune2fs -c 0 /dev/mapper/vdb--vg-vdb--lv
tune2fs -m 0 /dev/mapper/vdb--vg-vdb--lv
mount /dev/mapper/vdb--vg-vdb--lv /data
echo "/dev/mapper/vdb--vg-vdb--lv /data ext4    defaults        0 0 " >>/etc/fstab
mkdir /data/server
mkdir /data/logs
sudo chown -R admin:admin /data/server
sudo chown -R admin:admin /data/logs
}


function firewalld {
#!/bin/bash
if ! which csf &>/dev/null 
then
yum install bind-utils perl-LWP-Protocol-https perl-libwww-perl -y
cd /usr/src
rm -fv csf.tgz
wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz
cd csf
sh install.sh

wget http://172.16.2.187/csf/ip.list -O - | cat >/etc/csf/csf.allow

sed -i '/TESTING = "1"/s//TESTING = "0"/g' /etc/csf/csf.conf
sed -i '/TCP_OUT = .*/s//TCP_OUT = "1:65535"/g' /etc/csf/csf.conf
sed -i '/RESTRICT_SYSLOG = .*/s//RESTRICT_SYSLOG = "1"/g' /etc/csf/csf.conf
fi
/bin/cp /etc/csf/csf.allow /etc/csf/csf.allow.bak
wget http://172.16.2.187/centos/ip.list -O - | cat >/etc/csf/csf.allow
csf -r
#sed -i 's/#.*//g' /etc/csf/csf.allow
#sort -u /etc/csf/csf.allow > a.txt
#cat a.txt > /etc/csf/csf.allow
#sed -i '/TESTING = "1"/s//TESTING = "0"/g' /etc/csf/csf.conf
#sed -i '/^TCP_OUT =.*/s//TCP_OUT = "1:65535"/g' /etc/csf/csf.conf
#sed -i '/^UDP_OUT =.*/s//UDP_OUT = "1:65535"/g' /etc/csf/csf.conf
#sed -i '/DROP_LOGGING = "1"/s//DROP_LOGGING = "0"/g' /etc/csf/csf.conf
#sed -i '/RESTRICT_SYSLOG = "0"/s//RESTRICT_SYSLOG = "1"/g' /etc/csf/csf.conf
#sed -i '/TCP_IN = .*/s//TCP_IN = "80,8080,443,18080,13081,3000"/g' /etc/csf/csf.conf
#grep -P '^TESTING =|^TCP_IN =|^UDP_OUT =|^DROP_LOGGING =|^RESTRICT_SYSLOG =|^TCP_OUT =|^UDP_IN =' /etc/csf/csf.conf
#csf -x
#csf -r | grep -q 'csf -e' && csf -e
}


function salt {
#Install salt-minion agent

rpm -qa|grep salt-minion &>/dev/null

if [ $? -eq 0 ] ;then

        echo -e "Install salt-minion agent \n\nok\n\n" >>/root/default.log

else
        yum -y install salt-minion
        mv /etc/salt/minion /etc/salt/minion.bak
        chkconfig salt-minion on
        service salt-minion start
        [  $? -ne 0  ] && echo -e "Install salt-minion agent\n\nsalt-minion客户端安装失败\n\n" >>/root/default.log  &&exit
        echo -e "Install salt-minion agent\n\nok\n\n" >>/root/default.log
fi
}

case $1 in
    sys)
    user
    system_change
    epel_repo
    zabbix_agent
    disk_mount
    firewalld
                ;;
    mysql)
     user
     system_change
     epel_repo
     mysql_soft
     zabbix_agent
                 ;;
    php)
    user
    system_change
    epel_repo
    nginx_repo
    expect_install
    yum_soft
    yum_php_m
    httpd_soft
    bcmath
    zabbix_agent
                ;;
    jdk)
    jdk
                ;;
    salt)
    user
    system_change
    epel_repo
    zabbix_agent
    salt_agent
                ;;

    *)
    echo "Usage:/bin/sh update.sh 'sys|mysql|php|jdk|salt|'"
                 ;;
    esac

cat <<yangc
+-------------------------------+
|                               ｜
｜ system is initialized ！！！ |
|                               |
+-------------------------------+
yangc
