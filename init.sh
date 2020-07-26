#! /usr/bin/env bash
###################
###     SSH     ###
###################
SSH_KEY=${1:-"id_ed25519"}
SSH_KEYPATH="$HOME/.ssh/$SSH_KEY"
SSH_FINGERPRINT=$(ssh-keygen -l -E md5 -f "$SSH_KEYPATH.pub" | awk '{ print $2 }' | cut -c 5-)

###################
###   DROPLET   ###
###################
NAME=${2:-"wg-$(date +%s)"}
REGION=${3:-"nyc1"}
IMAGE=${4:-"ubuntu-20-04-x64"}
SIZE=${5:-"s-1vcpu-1gb"}

if [[ -z $DIGITAL_OCEAN_TOKEN ]]; then
    echo "Digital Ocean access token must be set"
    exit 1
fi

trap 'cleanup' ERR SIGINT SIGTERM SIGKILL
#######################################
# Cleans up wireguard interface and deletes droplet
#######################################
function cleanup {
    if [[ -n $(ip addr | grep wg0) ]]; then
        echo "Shutting down wg0 connection"
        sudo wg-quick down wg0
    fi
    echo "Removing droplet..."
    doctl compute droplet delete $NAME -f
    exit 1
}

#######################################
# Timeout until counter is reached, or command executes
# Arguments:
#   Command to execute
# Outputs:
#   0 or 1 if counter is maxed out
#######################################
function wait_til {
    local counter=0
    until [[ $counter -eq 20 ]] || $1; do
        echo "Waiting for $((++counter))"
        sleep $counter
    done
    [[ $counter -lt 20 ]]
}

#######################################
# Execute a command on the droplet
# Arguments:
#   Command
# Outputs:
#   stdout
#######################################
function exec_droplet {
    doctl compute ssh $NAME \
        --ssh-key-path $SSH_KEYPATH \
        --ssh-command "$@"
}

#######################################
# Creates a new wireguard droplet
#######################################
function create_droplet {
    echo "Creating droplet..."
    doctl compute droplet create \
        $NAME \
        --size $SIZE \
        --image $IMAGE \
        --region $REGION \
        --tag-name "wireguard" \
        --user-data "$(envsubst '${DIGITAL_OCEAN_TOKEN}' < cloud-init-user-script.sh)" \
        --ssh-keys $SSH_FINGERPRINT \
        --enable-ipv6 \
        --wait 
    echo "Droplet is now active!"

    IPv4=$(doctl compute droplet list $NAME --format 'Public IPv4' | tail -n 1)
    echo "IP is $IPv4"
}

#######################################
# Waits until port 22/TCP is open
# Outputs:
#   stderr if can not connect
#######################################
function wait_for_ssh {
    echo "Waiting for SSH to become available"
    wait_til "nc -vz $IPv4 22"
    if [[ $? == 1 ]]; then
        echo 'Could not connect with SSH' >&2
    fi
}

#######################################
# Authorize SSH connections to droplet 
#######################################
function authorize_ssh_connection {
    echo "Authorizing SSH connection to droplet"
    ssh-keyscan -H $IPv4 >> $HOME/.ssh/known_hosts
}

#######################################
# Waits until port 51820/UDP is open
# Outputs:
#   stderr if can not connect
#######################################
function wait_for_wireguard {
    echo "Waiting for Wireguard to become available"
    wait_til "nc -uvz $IPv4 51820"
    if [[ $? == 1 ]]; then
        echo 'Could not connect with WireGuard' >&2
    fi
}

#######################################
# Creates a local wireguard client
#######################################
function create_wireguard_client {
    umask 077
    wg genkey | tee privatekey | wg pubkey > publickey
    local CLIENT_PRIVATE_KEY=$(cat privatekey)
    local SERVER_PUBLIC_KEY=$(exec_droplet "cat /publickey")
    local TMP_FILE=$(tempfile)

cat << EOF > $TMP_FILE
[Interface]
Address = 10.0.0.2/32
Address = fd86:ea04:1111::2/128
PrivateKey = $CLIENT_PRIVATE_KEY
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $IPv4:51820
AllowedIPs = 0.0.0.0/0, ::/0
EOF

    sudo mv $TMP_FILE /etc/wireguard/wg0.conf
}

#######################################
# Allows client to connect to server
#######################################
function add_client_to_server {
    local CLIENT_PUBLIC_KEY=$(cat publickey)
    exec_droplet "wg set wg0 peer $CLIENT_PUBLIC_KEY allowed-ips 10.0.0.2/32,fd86:ea04:1111::2/128"
    exec_droplet "wg-quick save wg0"
}

#######################################
# Initialization function
#######################################
function init {
    create_droplet
    wait_for_ssh
    authorize_ssh_connection
    wait_for_wireguard
    create_wireguard_client
    add_client_to_server
    sudo wg-quick up wg0
}

init