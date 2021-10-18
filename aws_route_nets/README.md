## The script that helps to manage routes based on AWS subnet ranges.

That small bash script will help to route source AWS traffic via particular gateway that different to default.\
AWS sub-network ip ranges based on the list that available by the link: https://ip-ranges.amazonaws.com/ip-ranges.json

## Requirements

- Tested on FreeBSD and Ubuntu Linux.
- Expected to be performed periodically.

Also please make sure that target GW has related gate to machine where you run that script.

## How to use

```
bash ./aws_routes.sh
```
By deffault it will behave like `route add -net 54.245.168.0/26 192.168.1.1`

### Parameters can be manage via variables like:

 - `ACTION=delete` # will delete all added routes
 - `GW_IP=192.168.0.1` # will change gateway ip

 ## How to delete previously added routes

 ```
 ACTION=delete bash ./aws_routes.sh
 ```