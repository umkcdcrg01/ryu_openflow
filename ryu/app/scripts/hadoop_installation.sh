#!/bin/bash
# Just incase add-apt-repository wont be found on your system, you need to run $ sudo apt-get install -y software-properties-common

HadoopUserLogin="sudo su - hadoopuser"

echo -n "##### For all the Hadoop Nodes #####"
echo "Are you installing for Hadoop Master mode or slave (M/S)?"
echo -n "Enter M or S [ENTER]: "
read mode

echo $mode
if [ $mode == 'M' ] ; then
	echo "Installing hadoop Master"
elif [ $mode == 'S' ] ; then
	echo "Installation hadoop slave"
else
	echo "wrong input"
	exit
fi

echo -n "add java repo"
sudo apt-get update
sudo apt-get install -y software-properties-common
sudo add-apt-repository ppa:webupd8team/java 
sudo apt-get update 
sudo apt-get install oracle-java7-installer -y 

# Updata Java runtime 
sudo update-java-alternatives -s java-7-oracle 
sud apt-get install -y vim

# Disable IPv6 (Skip this step if you are not using IPv6)
sudo sed -i 's/net.ipv6.bindv6only\ =\ 1/net.ipv6.bindv6only\ =\ 0/' \ /etc/sysctl.d/bindv6only.conf && sudo invoke-rc.d procps restart

echo -n "Setting up a Hadoop User" 
sudo addgroup hadoopgroup 
sudo adduser hadoopuser 
sudo adduser hadoopuser hadoopgroup 
# sudo delgroup hadoopgroup
# sudo deluser hadoopuser

echo -n "#####For Master node only #####"
if [ $mode == 'M' ]; then
	echo -n "Login as hadoopuser and Generate ssh key "
	$HadoopUserLogin -c "whoami"
	
	$HadoopUserLogin -c "ssh-keygen -t rsa -P ''"
	#Authorize the key to enable password less ssh 
	$HadoopUserLogin -c "cat /home/hadoopuser/.ssh/id_rsa.pub >> /home/hadoopuser/.ssh/authorized_keys "
	$HadoopUserLogin -c "chmod 600 ~/.ssh/authorized_keys"

	echo -n "You need to copy id_ras.pub to slaves authorized_keys"
	echo -n "Also add hosts's IP in your hadoop slaves files"
	

	#Copy this key to slave-1 to enable password less ssh 
	#$ ssh-copy-id -i ~/.ssh/id_rsa.pub slaves/IPaddress 
	#Make sure you can do a password less ssh using following command. 
	#$ ssh slaves/IPaddress
fi

echo -n "##### For all nodes #####"

$HadoopUserLogin -c "wget  http://apache.mirrors.ionfish.org/hadoop/common/hadoop-2.6.0/hadoop-2.6.0.tar.gz 
tar xzvf hadoop-2.6.0.tar.gz" 
# change hadoop source folder to hadoop (not necessary, just for easy remember purpose) 
$HadoopUserLogin -c "mv hadoop-2.6.0 hadoop"
# set up environment variables for Master and slaves 
$HadoopUserLogin -c "cat >> ~/.bashrc << EOF
# Set HADOOP_HOME 
export HADOOP_HOME=/home/hadoopuser/hadoop 
# Set JAVA_HOME 
export JAVA_HOME=/usr/lib/jvm/java-7-oracle 
# Add Hadoop bin and sbin directory to PATH 
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/bin:/sbin:/home/hadoopuser/hadoop/bin:/usr/lib/jvm/java-7-oracle/bin:/home/hadoopuser/hadoop/bin:/usr/lib/jvm/java-7-oracle/bin:/home/hadoopuser/hadoop/sbin:/usr/lib/jvm/java-7-oracle/sbin
EOF
"
$HadoopUserLogin -c  "source ~/.bashrc"

$HadoopUserLogin -c  'echo -n " need to mannualy update hadoop-env" '
$HadoopUserLogin -c 'echo -n "hadoop-env.sh # export JAVA_HOME=/usr/lib/jvm/java-7-oracle"'

echo -n "udpate core-site.xml for all nodes"
$HadoopUserLogin -c  'cat > /home/hadoopuser/hadoop/etc/hadoop/core-site.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="configuration.xsl"?>
<configuration>
    <property>
     <name>hadoop.tmp.dir</name>
     <value>/home/hadoopuser/tmp</value>
     <description>Temporary Directory.</description>
   </property>

   <property>
     <name>fs.defaultFS</name>
     <value>hdfs://192.168.1.9:54310</value>
     <description>Use HDFS as file storage engine</description>
   </property>
</configuration>
EOF
'


echo -n "##### Update Master only #####"

if [ $mode == 'M' ]; then
	echo -n "update master mapred-site.xml"
	$HadoopUserLogin -c 'cat > /home/hadoopuser/hadoop/etc/hadoop/mapred-site.xml << EOF
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="configuration.xsl"?>
<configuration>
   <property>
    <name>mapreduce.jobtracker.address</name>
    <value>http://192.168.1.9:54311</value>
    <description>The host and port that the MapReduce job tracker runs
     at. If “local”, then jobs are run in-process as a single map
     and reduce task.
   </description>
   </property>
   <property>
    <name>mapreduce.framework.name</name>
    <value>yarn</value>
    <description>The framework for running mapreduce jobs</description>
   </property>
</configuration>
EOF
'
fi

echo -n "##### For all nodes #####"
echo -n "update hdfs-site.xml for all nodes"
$HadoopUserLogin -c 'cat > /home/hadoopuser/hadoop/etc/hadoop/hdfs-site.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="configuration.xsl"?>
<configuration>
    <property>
     <name>dfs.replication</name>
     <value>2</value>
     <description>Default block replication.
      The actual number of replications can be specified when the file is created.
      The default is used if replication is not specified in create time.
     </description>
    </property>
    <property>
     <name>dfs.namenode.name.dir</name>
     <value>/home/hadoopuser/hdfs/namenode</value>
     <description>Determines where on the local filesystem the DFS name node should store the name table(fsimage). If this is a comma-delimited list of directories then the name table is replicated in all of the directories, for redundancy.
     </description>
    </property>
    <property>
     <name>dfs.datanode.data.dir</name>
     <value>/home/hadoopuser/hdfs/datanode</value>
     <description>Determines where on the local filesystem an DFS data node should store its blocks. If this is a comma-delimited list of directories, then data will be stored in all named directories, typically on different devices. Directories that do not exist are ignored.
     </description>
    </property>
</configuration>
EOF
'
echo -n "update yarn-site.xml"

$HadoopUserLogin -c 'cat > /home/hadoopuser/hadoop/etc/hadoop/yarn-site.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="configuration.xsl"?>
<configuration>
        <property>
         <name>yarn.nodemanager.aux-services</name>
         <value>mapreduce_shuffle</value>
        </property>
        <property>
         <name>yarn.resourcemanager.scheduler.address</name>
         <value>192.168.1.9:8030</value>
        </property>
        <property>
         <name>yarn.resourcemanager.address</name>
         <value>192.168.1.9:8032</value>
        </property>
        <property>
          <name>yarn.resourcemanager.webapp.address</name>
          <value>0.0.0.0:8088</value>
        </property>
        <property>
          <name>yarn.resourcemanager.resource-tracker.address</name>
          <value>192.168.1.9:8031</value>
        </property>
        <property>
          <name>yarn.resourcemanager.admin.address</name>
          <value>192.168.1.9:8033</value>
        </property>
	</configuration>
EOF
'

echo -n "done installation and configure..NEXT...."

echo -n "1. you need to edit master slaves file
		2. start your master node $ hdfs namenode -format
		3. $ start-dfs.sh
		4. start-yarn.sh
		5. need to mannualy update hadoop-env.xml
			change at hadoop-env.sh 
			# export JAVA_HOME=/usr/lib/jvm/java-7-oracle"


exit