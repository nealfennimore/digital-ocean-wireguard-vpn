# WireGuard Digital Ocean VPN

## What it does
This script automatically creates an Wireguard VPN droplet and then connects to it. If there's no connection through Wireguard for 15 minutes, it then automatically destroys the droplet.

## Installation

Install wireguard on your machine:
```sh
sudo add-apt-repository ppa:wireguard/wireguard -y
sudo apt install wireguard -y
```

Follow the instructions to install [doctl](https://github.com/digitalocean/doctl#installing-doctl) and then [authenticate](https://github.com/digitalocean/doctl#authenticating-with-digitalocean).

Ensure an [access token](https://cloud.digitalocean.com/account/api/tokens) is available on the shell as `DIGITAL_OCEAN_TOKEN`.

Then run the init script.
```sh
./init.sh
```

It should then boot up a droplet and connect to it via wireguard.