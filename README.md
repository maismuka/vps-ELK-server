# vps-ELK-server

1. you must have a purchased/subsribe a domain name server (DNS) and a virtual private server (VPS)

2. all purchased item are on your own affordability

3. this project will create an ELK server in Digital Ocean VPS, with my DNS from google domain

4. multiple client from wide range of clients/nodes that collect .json file

5. I am using debian 18.04 LTS

6. your machine must have atleast 2Gb of RAM



For this guide to work, all the steps are must in the correct (suggested) order;

-Elasticsearch

-Kibana

-Logstash

-Beats





## A. Installing Elasticsearch

It started with Elasticsearch…
The open source, distributed, RESTful, JSON-based search engine. Easy to use, scalable and flexible, it earned hyper-popularity among users and a company formed around it, you know, for search.

`sudo apt update && apt upgrade`

Import the Elasticsearch PGP Key

`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -`

Add Elasticsearch 7.x APT repository

`echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list`

Install Elasticsearch 7.0.0 on Ubuntu 18.04/Debian 9.8

Note that Elasticsearch includes a bundled version of OpenJDK from the JDK maintainers

```
apt update
apt-get install apt-transport-https
apt install elasticsearch
```

If everything goes well, you can find the Elasticsearch configuration file as **/etc/elasticsearch/elasticsearch.yml.**


To configure Elasticsearch to start on system boot, run the following commands:

`systemctl daemon-reload
systemctl enable elasticsearch`

To check the status, run the command below;

`systemctl status elasticsearch`

If the status is green and stated as **Active** , then you are good to go

Use `curl` command to check Elasticsearch status

`curl -X GET "localhost:9200/"`


###### Elasticsearch is listening on localhost by default. If you are running Elasticsearch and need to access it from outside, you need to change the network bind address. However, for this to work, you need to __configure single-node discovery__

`nano /etc/elasticsearch/elasticsearch.yml`

make few changes on Network and Discovery

please remember that the IP is your server VPS ip

```
# ---------------------------------- Network -----------------------------------
#
# Set the bind address to a specific IP (IPv4 or IPv6):
#
#network.host: 192.168.0.1
network.host: 192.168.0.101
#
# Set a custom port for HTTP:
#
#http.port: 9200
http.port: 9200
#
# For more information, consult the network module documentation.
# 

# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
#discovery.seed_hosts: ["host1", "host2"]
#
# Bootstrap the cluster using an initial set of master-eligible nodes:
#
#cluster.initial_master_nodes: ["node-1", "node-2"]
#
# For more information, consult the discovery and cluster formation module documentation.
#
discovery.type: single-node
```

Restart Elasticsearch and confirm that it is listening on an interface IP.

`sudo systemctl restart logstash.service`

`curl -X GET http://192.168.0.101:9200`

And you will get a reply and it is up and running



## B. Installing Kibana

Kibana lets you visualize your Elasticsearch data and navigate the Elastic Stack so you can do anything from tracking query load to understanding the way requests flow through your apps.

`sudo apt install kibana`

then enable Kibana on system reboot

```
systemctl daemon-reload
systemctl start kibana
systemctl enable kibana
```

Kibana is set to run on localhost:5601 by default. Therefore, to add some layer of HTTPS security, you can install and configure Nginx to proxy the connection to Kibana via a publicly accessible interface IP. If you choose to use Nginx instead of exposing Kibana, you can proceed as follows;

`sudo apt install nginx`

we will use self signed SSL/TLS certificates

to generate self signed certificates;

`sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/kibana-selfsigned.key -out /etc/ssl/certs/kibana-selfsigned.crt`

Also for more security, we will use Deffie-hellman key exchange

`sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048`

and this will take a few minutes

Now, to create Nginx sample configuration. Find more at [https://cipherli.st/](https://cipherli.st/) or read further at [https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html](https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html)

`sudo nano vim /etc/nginx/sites-available/kibana`

```
server {
	listen 80;
	server_name elk.example.com;
	return 301 https://$host$request_uri;
}
server {
	listen 443 ssl;
	server_name elk.example.com;

	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;

    	ssl_certificate /etc/ssl/certs/kibana-selfsigned.crt;
	ssl_certificate_key /etc/ssl/private/kibana-selfsigned.key;

	ssl_protocols TLSv1.2 TLSv1.3;
	ssl_prefer_server_ciphers on; 
	ssl_dhparam /etc/nginx/dhparam.pem;
	ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
	ssl_ecdh_curve secp384r1;
	ssl_session_timeout  10m;
	ssl_session_cache shared:SSL:10m;
	resolver 192.168.42.129 8.8.8.8 valid=300s;
	resolver_timeout 5s; 
	add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
	add_header X-Frame-Options DENY;
	add_header X-Content-Type-Options nosniff;
	add_header X-XSS-Protection "1; mode=block";

	access_log  /var/log/nginx/kibana_access.log;
	error_log  /var/log/nginx/kibana_error.log;

	auth_basic "Authentication Required";
	auth_basic_user_file /etc/nginx/kibana.users;

	location / {
	        proxy_pass http://localhost:5601;
        	proxy_http_version 1.1;
	        proxy_set_header Upgrade $http_upgrade;
        	proxy_set_header Connection 'upgrade';
	        proxy_set_header Host $host;
        	proxy_cache_bypass $http_upgrade;
	}
}
```

please noted that you may have to change `server_name` and `resolver`. 

you need to change configuration file `/etc/kibana/kibana.yml`

`nano /etc/kibana/kibana.yml`

uncomment and change the `elasticsearch.host:`

```
# The URLs of the Elasticsearch instances to use for all your queries.
elasticsearch.hosts: ["http://192.168.0.101:9200"]
```

To configure Nginx User authentication, you need to create users and their password. These authentication details will be saved in the file, `/etc/nginx/kibana.users`

Use openssl command to generate the authentication credentials as shown below. Remember replace `USERNAME` and `PASSWORD` to your liking

`sudo printf "USERNAME:$(openssl passwd -crypt PASSWORD)\n" > /etc/nginx/kibana.users`

enable Kibana Nginx configuration

`sudo ln /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/`

check Nginx syntax

`sudo nginx -t`

restart Nginx

`sudo systemctl restart nginx.service`

if you have enabled firewall in your ubuntu, allow HTTP and HTTPS Nginx connections

`sudo ufw allow 'Nginx Full'`

You should now be able to access Kibana dashboard via the server fully qualified hostname, `https://elk.example.com` in this case. Accept the risk of using the self-signed certificate and proceed. Before you can access the Kibana dashboard, you will be required to provide the authentication credentials set above

###### Noted that we do not have any data yet. Henceforth, we are going to ship our data from another client using Logstash and Beats




## C. Installing Logstash

Logstash is an open source, server-side data processing pipeline that ingests data from a multitude of sources simultaneously, transforms it, and then sends it to your favorite "stash."

First, is to install a Java version 8. This will get you installed the latest java version

`sudo apt install openjdk-8-jdk`

check java version

`java -version`

`OpenJDK Runtime Environment (build 1.8.0_222-8u222-b10-1ubuntu1~18.04.1-b10)`

###### please be aware that you might get newer java build version than this

Installing Logstash

`sudo apt install logstash`

###### Logstash plugin

create `nano /etc/logstash/conf.d/beats-input.conf`

```
input {
  beats {
    port => 5044
  }
}
```

###### Logstash Filter

For demonstration purposes, we are going to configure beats to collect SSH authentication events from Ubuntu/CentOS systems. Hence, we are going to create a filter to process such kind of events as shown below

```
May  1 13:15:23 elk sshd[1387]: Failed password for testuser from 192.168.0.102 port 60004 ssh2
May  1 13:08:30 elk sshd[1338]: Accepted password for testuser from 192.168.0.102 port 59958 ssh2
```

create `.conf` file

`vim /etc/logstash/conf.d/ssh-auth-filter.conf`

```
filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP:timestamp}\s+%{IPORHOST:dst_host}\s+%{WORD:syslog_program}\[\d+\]:\s+(?<status>\w+\s+password)\s+for\s+%{USER:auth_user}\s+from\s+%{SYSLOGHOST:src_host}.*" }
    add_field => { "activity" => "SSH Logins" }
    add_tag => "linux_auth"
    }
}
```

###### Logstash Output

`vim /etc/logstash/conf.d/elasticsearch-output.conf`

```
output {
   elasticsearch {
     hosts => ["localhost:9200"]
     manage_template => false
     index => "ssh_auth-%{+YYYY.MM}"
 }
 stdout { codec => rubydebug }
}
```

testing Logstash configuration

`sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t`

this will take time. After it says `Config Validation Result: OK. Exiting Logstash`, then you are good to go

enable Logstash to run at boot

`systemctl start logstash.service`

`systemctl enable logstash.service`



## D. Installing Filebeat

Add Elastic Stack 7 APT Repository

download and install the Elastic Stack Repo public signing key

`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -`

Create the Elastic Stack 7 Apt repository.

`echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list`

###### Install Filebeat 7.x

```
apt-get install apt-transport-https
apt update
apt install filebeat
```

By default, Filebeat area receiving logs from Elasticsearch. But in this configurations, I'll be using Filebeat to send to Logstash.
Hence, we need to edit Filebeat configuration file

`nano /etc/filebeat/filebeat.yml`

comment all in the Elasticsearch section

```
#================================ Outputs =====================================

# Configure what output to use when sending the data collected by the beat.

#-------------------------- Elasticsearch output ------------------------------
# output.elasticsearch:
  # Array of hosts to connect to.
  # hosts: ["localhost:9200"]

  # Optional protocol and basic auth credentials.
  #protocol: "https"
  #username: "elastic"
  #password: "changeme"
```

uncomment Logstash output

```
#----------------------------- Logstash output --------------------------------
output.logstash:
  # The Logstash hosts
  hosts: ["192.168.0.101:5044"]
  ```

Then, enable Filebeat System Module. Logstash Filter was configured to parse system auth events. 
System module collects and parses logs created by the system logging service of common Unix/Linux based distributions. This module is disabled by default.

`filebeat modules enable system`

To load the index template in Elasticsearch, first we need to test the live connection using `telnet`

`telnet 192.168.0.101 9200`

```
Trying 192.168.0.101...
Connected to 192.168.0.101.
Escape character is '^]'.
```

Load the Index Template

`filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["192.168.0.101:9200"]'`

To verify Elasticsearch Data Reception, we need to perform successful and failed login on the system with Filebeat installed. After that login to Elastic Stack server and verify if Elasticsearch is receiving data

`curl -X GET 192.168.0.101:9200/_cat/indices?v`

you will get something like this

```

health status index                            uuid                   pri rep docs.count docs.deleted store.size pri.store.size
yellow open   filebeat-7.0.0-2019.05.01-000001 3vhNqUvLS6CTgJQlSkp1Lg   1   1          0            0       283b           283b
green  open   .kibana_1                        w-vOaD46QGa7LldMAvJVtw   1   0          3            1       20kb           20kb
yellow open   ssh_auth-2019.05                 TyZHEQx_SR2q05a8yCEU-A   1   1       5940            0      2.2mb          2.2mb
green  open   .kibana_task_manager             XhZ5kmOMRzWvQ3VDEvoNRA   1   0          2            0     45.4kb         45.4kb
```

remember, the log file only created after a successfull/unsuccessfull login into kibana website

our log file earlier was stored in `ssh_auth-2019.05`

Check `ssh_auth-2019.05` index;

`curl -X GET 192.168.0.101:9200/ssh_auth-*/_search?pretty`

```
{
  "took" : 19044,
  "timed_out" : false,
  "_shards" : {
    "total" : 1,
    "successful" : 1,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 10000,
      "relation" : "gte"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "ssh_auth-2019.09",
        "_type" : "_doc",
        "_id" : "kqf_-WwB0cJPgHQw5Nad",
        "_score" : 1.0,
        "_source" : {
          "service" : {
            "type" : "system"
          },
          "log" : {
            "offset" : 3660189,
            "file" : {
              "path" : "/var/log/syslog"
            }
          },
          "message" : "Sep  4 01:57:17 maismukaserv logstash[22108]:     },",
          "event" : {
            "module" : "system",
            "timezone" : "+00:00",
            "dataset" : "system.syslog"
          },
          "ecs" : {
            "version" : "1.0.1"
          },
          "fileset" : {
            "name" : "syslog"
          },
          "input" : {
            "type" : "log"
          },
          "host" : {
            "os" : {
              "codename" : "bionic",
              "name" : "Ubuntu",
              "version" : "18.04.3 LTS (Bionic Beaver)",
              "kernel" : "4.15.0-58-generic",
              "platform" : "ubuntu",
              "family" : "debian"
            },
            "name" : "maismukaserv",
            "id" : "5e6c595f5f7b460b94d1bb6f9b45b5c2",
            "containerized" : false,
            "architecture" : "x86_64",
            "hostname" : "maismukaserv"
          },
          "cloud" : {
            "region" : "sgp1",
            "instance" : {
              "id" : "157465293"
            },
            "provider" : "digitalocean"
          },
          "tags" : [
            "beats_input_codec_plain_applied",
            "_grokparsefailure"
          ],
          "@version" : "1",
          "agent" : {
            "hostname" : "maismukaserv",
```

the lists goes on...

The Elasticsearch was configured successfully! Now to add the log index into Kibana
























