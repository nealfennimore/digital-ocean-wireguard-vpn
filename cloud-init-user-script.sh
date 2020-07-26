#! /usr/bin/env bash
set -euo pipefail

########################
### SCRIPT VARIABLES ###
########################

# Name of the user to create and grant sudo privileges
USERNAME=wireguard

# Whether to copy over the root user's `authorized_keys` file to the new sudo
# user.
COPY_AUTHORIZED_KEYS_FROM_ROOT=true

# Additional public keys to add to the new sudo user
# OTHER_PUBLIC_KEYS_TO_ADD=(
#     "ssh-rsa AAAAB..."
#     "ssh-rsa AAAAB..."
# )
OTHER_PUBLIC_KEYS_TO_ADD=(
)

####################
### SCRIPT LOGIC ###
####################

# Add sudo user and grant privileges
useradd --create-home --shell "/bin/bash" --groups sudo "${USERNAME}"

# Check whether the root account has a real password set
encrypted_root_pw="$(grep root /etc/shadow | cut --delimiter=: --fields=2)"

if [ "${encrypted_root_pw}" != "*" ]; then
    # Transfer auto-generated root password to user if present
    # and lock the root account to password-based access
    echo "${USERNAME}:${encrypted_root_pw}" | chpasswd --encrypted
    passwd --lock root
else
    # Delete invalid password for user if using keys so that a new password
    # can be set without providing a previous value
    passwd --delete "${USERNAME}"
fi

# Expire the sudo user's password immediately to force a change
chage --lastday 0 "${USERNAME}"

# Create SSH directory for sudo user
home_directory="$(eval echo ~${USERNAME})"
mkdir --parents "${home_directory}/.ssh"

# Copy `authorized_keys` file from root if requested
if [ "${COPY_AUTHORIZED_KEYS_FROM_ROOT}" = true ]; then
    cp /root/.ssh/authorized_keys "${home_directory}/.ssh"
fi

# Add additional provided public keys
for pub_key in "${OTHER_PUBLIC_KEYS_TO_ADD[@]}"; do
    echo "${pub_key}" >> "${home_directory}/.ssh/authorized_keys"
done

# Adjust SSH configuration ownership and permissions
chmod 0700 "${home_directory}/.ssh"
chmod 0600 "${home_directory}/.ssh/authorized_keys"
chown --recursive "${USERNAME}":"${USERNAME}" "${home_directory}/.ssh"

# Disable root SSH login with password
sed --in-place 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
if sshd -t -q; then
    systemctl restart sshd
fi

# Add exception for SSH and Wireshark and then enable UFW firewall
ufw allow 22/tcp
ufw allow 51820/udp
ufw --force enable
ufw status verbose

# Update system to allow IPv4 and IPv6 forwarding
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/' /etc/sysctl.conf
sysctl -p


###################
###  WIREGUARD  ###
###################

add-apt-repository ppa:wireguard/wireguard -y
apt install wireguard -y

umask 077
wg genkey | tee privatekey | wg pubkey > publickey

PRIVATE_KEY=$(cat privatekey)

cat << EOF > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.0.0.1/24
Address = fd86:ea04:1111::1/64
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
SaveConfig = true
EOF

wg-quick up wg0
systemctl enable wg-quick@wg0

###################
###    CRON     ###
###################

# Install cron dependencies
apt install jq -y

# Create cron script
cat << 'EOF' > /usr/local/bin/destroy-droplet
# /usr/bin/env bash
wg | grep -v 'latest handshake' > /tmp/wg-output

if [[ -f "/tmp/wg-output-old" ]]; then

    # If no difference, then we kill the server
    if [[ -z $(diff /tmp/wg-output /tmp/wg-output-old) ]]; then

        # Get the host name
        machine_name=$(hostname)

        # Get all the current tagged droplets
        droplets=$(
            curl -s \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer $DIGITAL_OCEAN_TOKEN" \
                "https://api.digitalocean.com/v2/droplets"
        )

        # Get the id from the current hostname
        id=$(echo $droplets | jq --arg hostname $machine_name '.droplets | map(select(.name == $hostname))[0].id')

        # Finally delete the machine
        curl -X DELETE \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $DIGITAL_OCEAN_TOKEN" \
            "https://api.digitalocean.com/v2/droplets/$id"
    fi
fi

mv /tmp/wg-output /tmp/wg-output-old

EOF

# Make sure cron script is executable
chmod +x /usr/local/bin/destroy-droplet

# Setup cron to occur every 15 minutes
echo "*/15 * * * * root /usr/local/bin/destroy-droplet" > /etc/cron.d/destroy-droplet

# Setup initial output for comparison in cron
wg | grep -v 'latest handshake' > /tmp/wg-output-old
