#!/usr/bin env python 
# -*- coding: utf-8 -*-

import subprocess
import os.path

def execRemote(cmd, target='root@localhost'):
    if '!returnIP' == cmd:
        return target.split('@')[-1]
    p = subprocess.Popen(['ssh', '-t', target, cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate()



def execLocal(cmd):
    if '!returnIP' == cmd:
        return '127.0.0.1'
    #print(cmd)
    p = subprocess.Popen(['bash', '-c', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate()

def addNetDev(devName='wg0', devType='wireguard', execFcn=execLocal):
    return execFcn('ip link add dev {} type {}'.format(devName, devType))

def addAddress(devName='wg0', address='192.168.50.0/24', execFcn=execLocal):
    return execFcn('ip address add dev {} {}'.format(devName, address))

def upLink(devName='wg0', execFcn=execLocal):
    return execFcn('ip link set up dev {}'.format(devName))

def kwFormat(**kwargs):
    if kwargs.values()[0] is None:
        return ''
    return '{} {}'.format(kwargs.keys()[0].replace('_','-'), kwargs.values()[0])

def setWG(devName='wg0', listen_port=None, private_key=None, peer=None, allowed_ips=None, endpoint=None, persistent_keepalive=None, execFcn=execLocal):
    return execFcn('wg set {} {}'.format(devName, ' '.join([kwFormat(listen_port=listen_port), kwFormat(private_key=private_key), kwFormat(peer=peer), kwFormat(allowed_ips=allowed_ips), kwFormat(endpoint=endpoint), kwFormat(persistent_keepalive=persistent_keepalive)])))

def createKeys(path='/tmp/wireguard/privkey', execFcn=execLocal):
    execFcn('mkdir -p {}'.format(os.path.dirname(path)))
    execFcn('touch {}'.format(path))
    execFcn('chmod 077 {}'.format(path))
    execFcn('wg genkey > {}'.format(path))
    return execFcn('wg pubkey < {}'.format(path))


def createInterface(devName='wg0', address='192.168.50.0/24', listen_port=None, privKeyPath='/tmp/wireguard/privkey', execFcn=execLocal):
    addNetDev(devName, execFcn=execFcn)
    addAddress(devName, address, execFcn=execFcn)
    upLink(devName, execFcn=execFcn)
    pubKey, err = createKeys(path=privKeyPath, execFcn=execFcn)
    print(setWG(devName, listen_port=listen_port, private_key=privKeyPath, execFcn=execFcn))
    return pubKey.replace('\n','').replace('\r','')


def getInterfacePubKey(devName='wg0', execFcn=execLocal):
    pubKey, err = execFcn('wg show {} public-key'.format(devName))
    return pubKey.replace('\n','').replace('\r','')

def getInterfacePort(devName='wg0', execFcn=execLocal):
    pubKey, err = execFcn('wg show {} listen-port'.format(devName))
    return pubKey.replace('\n','').replace('\r','')

def addPeer(devName='wg0', peer=None, endpoint=None, allowed_ips='0.0.0.0/0', persistent_keepalive=25, execFcn=execLocal):
    print(setWG(devName, peer=peer, allowed_ips=allowed_ips, endpoint=endpoint, persistent_keepalive=persistent_keepalive, execFcn=execFcn))


    # use this function if interface on server exists
def connect2server(remoteExecFcn, remoteDevName='wg0', remoteAllowedIPs='192.168.91.0/24', localExecFcn=execLocal, localDevName='wg0', localIP='192.168.91.2/24'):
    localPubKey = createInterface(localDevName, localIP, execFcn=localExecFcn)
    remotePubKey = getInterfacePubKey(remoteDevName, remoteExecFcn)
    remotePort = getInterfacePort(remoteDevName, remoteExecFcn)
    remoteIP = remoteExecFcn('!returnIP')
    addPeer(remoteDevName, localPubKey, allowed_ips=remoteAllowedIPs, execFcn=remoteExecFcn)
    addPeer(localDevName, remotePubKey, '{}:{}'.format(remoteIP, remotePort), execFcn=localExecFcn)



def createEndpoint(devName='wg0', address='192.168.50.0/24', peer=None, endpoint=None, allowed_ips='0.0.0.0/0', listen_port=None, privKeyPath='/tmp/wireguard/privkey', persistent_keepalive=25, execFcn=execLocal):
    addNetDev(devName, execFcn=execFcn)
    addAddress(devName, address, execFcn=execFcn)
    upLink(devName, execFcn=execFcn)
    #pubKey = createKeys(path=privKeyPath, execFcn=execFcn)
    print(setWG(devName, listen_port=listen_port, private_key=privKeyPath, peer=peer, allowed_ips=allowed_ips, endpoint=endpoint, persistent_keepalive=persistent_keepalive, execFcn=execFcn))
    #return pubKey


def createTunnel(execFcnA, execFcnB=execLocal):
    pubKeyA = createInterface('wg3', '192.168.91.1/24', listen_port=51821, execFcn=execFcnA)
    pubKeyB = createInterface('wg3', '192.168.91.2/24', execFcn=execFcnB)
    #print(pubKeyA)
    addPeer('wg3', pubKeyB, allowed_ips='192.168.91.0/24', execFcn=execFcnA)
    addPeer('wg3', pubKeyA, '94.16.116.218:51821', execFcn=execFcnB)



connect2server(lambda x: execRemote(x, 'root@94.16.116.218'), 'wg3', localDevName='wg3')

#print(getInterfacePubKey('wg0', lambda x: execRemote(x, 'root@94.16.116.218')))
#createTunnel(lambda x: execRemote(x, 'root@94.16.116.218'))

#print(execLocal(addNetDev('wg1')))

#print(execLocal(addAddress('wg0', '192.168.50.2/24')))


#print(execLocal(setWG('wg0', listen_port=33720, private_key='/home/stefan/privkey2', peer='VVNn2H4i1QGNYqPiXTIXDhtKkK5a+zReWFHqqojYbB8=', allowed_ips='0.0.0.0/0', endpoint='94.16.116.218:51820', persistent_keepalive=25)))

#print(execLocal(upLink('wg0')))

#myTarget = 'root@94.16.116.218'




#print(remoteAddNetDev(target='root@94.16.116.218'))
