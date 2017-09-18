#!/bin/sh
MASTER_NAME="redis-master"
SLAVE_NAME="redis-slave"
IMAGE='redis:latest'
PASSWORD='asdf'
DETACHED='true'
PERSIST_PATH='/home/vagrant/dragonflow/vagrant/provisioning/redis/redis.conf:/usr/local/etc/redis/redis.conf'
CONFIG_PATH='/usr/local/etc/redis/redis.conf'

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

echo "Creating Cluster"
# start cluster master
#-e REDIS_PASSWORD=$PASSWORD \
    #-e REDIS_REPLICATION_MODE=master \
    docker run --name $MASTER_NAME\
    -e ALLOW_EMPTY_PASSWORD=yes \
    -v $PERSIST_PATH \
    -d=$DETACHED \
    -p 6379:6379 \
    $IMAGE \
   redis-server $CONFIG_PATH
# start cluster slave
#-e REDIS_MASTER_PASSWORD=$PASSWORD \
    #-e REDIS_PASSWORD=$PASSWORD \
    #docker run --name $SLAVE_NAME \
    #--link redis-master:master \
    #-e REDIS_REPLICATION_MODE=slave \
    #-e REDIS_MASTER_HOST=master \
    #-e REDIS_MASTER_PORT_NUMBER=6379 \
    #-e ALLOW_EMPTY_PASSWORD=yes \
    #-d=$DETACHED \
    #$IMAGE
