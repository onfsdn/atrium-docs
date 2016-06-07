
sudo kill -9 `ps -ef | grep "./cli.py" | grep -v grep | awk '{print $2}'`
sudo kill -9 `ps -ef | grep "ssh -X" | grep -v grep | awk '{print $2}'`
sudo mn -c
sudo kill -9 `ps -ef |grep "sudo mn" |grep -v grep | awk '{print $2}'`
sudo kill -9 `ps -ef |grep "/usr/local/bin/mn" |grep -v grep | awk '{print $2}'`
sudo kill -9 `ps -ef | grep "zebra" | grep -v grep | awk '{print $2}'`
sudo kill -9 `ps -ef | grep "bgpd" | grep -v grep | awk '{print $2}'`

