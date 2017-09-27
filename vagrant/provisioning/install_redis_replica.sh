#!/bin/sh
MASTER_NAME="redis-master"
SLAVE_NAME="redis-slave"
IMAGE='redis:3'
#IMAGE='redis:latest'
PASSWORD='asdf'
DETACHED='true'
PERSIST_PATH='/home/vagrant/dragonflow/vagrant/provisioning/redis/redis.conf:/usr/local/etc/redis/redis.conf'
CONFIG_PATH='/usr/local/etc/redis/redis.conf'
NETWORK_NAME='app-tier'

# install docker if not installed
install_docker(){

    curl -fsSL get.docker.com -o get-docker.sh
    sh get-docker.sh
    sudo usermod -aG docker vagrant
    echo "WARNING: Created docker user: re-login required"
    exit 0
}

which docker
if [ $? -eq 0 ]
then
    docker --version | grep "Docker version"
    if [ $? -eq 0 ]
    then
        echo "docker existing"
    else
        echo "installing docker"
        install_docker
    fi
else
    echo "installing  docker"
    install_docker
fi
echo "fixing linux kernel for redis\necho never > /sys/kernel/mm/transparent_hugepage/enabled"
sudo echo "never" > /sys/kernel/mm/transparent_hugepage/enabled

echo "removing old containers"
docker rm $MASTER_NAME
docker rm $SLAVE_NAME
# creating network
docker network rm $NETWORK_NAME
docker network create --subnet=172.18.0.0/16 $NETWORK_NAME


#echo "Single instace Cluster disabled for testing"
#docker run --name $MASTER_NAME\
#    -e ALLOW_EMPTY_PASSWORD=yes \
#    --network $NETWORK_NAME \
#    -d=$DETACHED \
#    -p 6379:6379 \
#    $IMAGE \
echo "Not implemented --> skip"
exit 0
echo "Creating Cluster"
#-e REDIS_PASSWORD=$PASSWORD \
docker run --name $MASTER_NAME\
    -e ALLOW_EMPTY_PASSWORD=yes \
    -e REDIS_REPLICATION_MODE=master \
    --network $NETWORK_NAME --ip 172.18.0.22 \
    -v $PERSIST_PATH \
    -d=$DETACHED \
    -p 6379:6379 \
    $IMAGE \
   redis-server $CONFIG_PATH

## start cluster slave
##-e REDIS_MASTER_PASSWORD=$PASSWORD \
#    #-e REDIS_PASSWORD=$PASSWORD \
docker run --name $SLAVE_NAME \
    --link redis-master:master \
    -e REDIS_REPLICATION_MODE=slave \
    -e REDIS_MASTER_HOST=172.18.0.22 \
    -e REDIS_MASTER_PORT_NUMBER=6379 \
    -e ALLOW_EMPTY_PASSWORD=yes \
    --network $NETWORK_NAME --ip 172.18.0.23 \
    -v $PERSIST_PATH \
    -d=$DETACHED \
    $IMAGE \
    redis-server $CONFIG_PATH
