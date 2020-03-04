import argparse
import boto.ec2
import sys, os
import time

if not boto.config.has_section('ec2'):
    boto.config.add_section('ec2')
    boto.config.setbool('ec2','use-sigv4',True)

#These are the parameters for the AWS account
your_key_path = ""
your_key_name = ""
instancetype = 't2.medium'


#secgroups are associated with the AWS account, which could be found by entering each region 
secgroups = {
    'us-east-1':'sg-0ae1197027d767da2',
    'us-west-1':'sg-e192bd98',
    'us-west-2':'sg-9eca16e0',
    'eu-west-1':'sg-1bd2d661', #Ireland
    'sa-east-1':'sg-fcf5849a',
    'ap-south-1':'sg-dc7d0eb7',
    'ap-southeast-1':'sg-33138b4a', #Singapore
    'ap-southeast-2':'sg-09e67670', #Sydney
    'ap-northeast-1':'sg-90fdf3e9', #Tokyo
    'ca-central-1':'sg-d0896abb',
}
regions = sorted(secgroups.keys())[::-1]

NameFilter = 'BEAT0'
    
def getAddrFromEC2Summary(s):
    return [
            x.split('ec2.')[-1] for x in s.replace(
                '.compute.amazonaws.com', ''
                ).replace(
                    '.us-west-1', ''    # Later we need to add more such lines
                    ).replace(
                        '-', '.'
                        ).strip().split('\n')]

def get_ec2_instances_ip(region):
    ec2_conn = boto.ec2.connect_to_region(region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
    if ec2_conn:
        result = []
        reservations = ec2_conn.get_all_reservations(filters={'tag:Name': NameFilter})
        for reservation in reservations:
            if reservation:       
                for ins in reservation.instances:
                    if ins.public_dns_name: 
                        currentIP = ins.public_dns_name.split('.')[0][4:].replace('-','.')
                        result.append(currentIP)
                        print currentIP
        return result
    else:
        print 'Region failed', region
        return None

def get_ec2_instances_id(region):
    ec2_conn = boto.ec2.connect_to_region(region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
    if ec2_conn:
        result = []
        reservations = ec2_conn.get_all_reservations(filters={'tag:Name': NameFilter})
        for reservation in reservations:    
            for ins in reservation.instances:
                print ins.id
                result.append(ins.id)
        return result
    else:
        print 'Region failed', region
        return None

def stop_all_instances(region):
    ec2_conn = boto.ec2.connect_to_region(region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
    idList = []
    if ec2_conn:
        reservations = ec2_conn.get_all_reservations(filters={'tag:Name': NameFilter})
        for reservation in reservations: 
            if reservation:   
                for ins in reservation.instances:
                    idList.append(ins.id)
        ec2_conn.stop_instances(instance_ids=idList)

def terminate_all_instances(region):
    ec2_conn = boto.ec2.connect_to_region(region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
    idList = []
    if ec2_conn:
        reservations = ec2_conn.get_all_reservations(filters={'tag:Name': NameFilter})
        for reservation in reservations:   
            if reservation:    
                for ins in reservation.instances:
                    idList.append(ins.id)
        ec2_conn.terminate_instances(instance_ids=idList)

def launch_new_instances(region, number):
    ec2_conn = boto.ec2.connect_to_region(region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
    dev_sda1 = boto.ec2.blockdevicemapping.EBSBlockDeviceType(delete_on_termination=True)
    dev_sda1.size = 8 # size in Gigabytes
    dev_sda1.delete_on_termination = True
    bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
    bdm['/dev/sda1'] = dev_sda1
    img = ec2_conn.get_all_images(filters={'name':'ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-20190406'})[0].id
    reservation = ec2_conn.run_instances(image_id=img, #'ami-df6a8b9b',  # ami-9f91a5f5
                                 min_count=number,
                                 max_count=number,
                                 key_name=your_key_name, 
                                 instance_type=instancetype,
                                 security_group_ids = [secgroups[region], ],
                                 block_device_map = bdm)
    for instance in reservation.instances:
        instance.add_tag("Name", NameFilter)
    return reservation


def start_all_instances(region):
    ec2_conn = boto.ec2.connect_to_region(region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key)
    idList = []
    if ec2_conn:
        reservations = ec2_conn.get_all_reservations(filters={'tag:Name': NameFilter})
        for reservation in reservations:    
            for ins in reservation.instances:
                idList.append(ins.id)
        ec2_conn.start_instances(instance_ids=idList)


def ipAll():
    result = []
    for region in regions:
        result += get_ec2_instances_ip(region) or []
    open('hosts','w').write('\n'.join(result))
    callFabFromIPList(result, 'removeHosts')
    callFabFromIPList(result, 'writeHosts')
    return result


def getIP():
    return [l for l in open('hosts', 'r').read().split('\n') if l]


def idAll():
    result = []
    for region in regions:
        result += get_ec2_instances_id(region) or []
    return result


def startAll():
    for region in regions:
        start_all_instances(region)


def stopAll():
    for region in regions:
        stop_all_instances(region)

from subprocess import check_output, Popen, call, PIPE, STDOUT
import fcntl
from threading import Thread
import platform

def callFabFromIPList(l, work):
    if platform.system() == 'Darwin':
        print Popen(['fab', '-i', your_key_path,
            '-u', 'ubuntu', '-H', ','.join(l), # We rule out the client
            work])
    else:
        print 'fab -i %s -u ubuntu -P -H %s %s' % (your_key_path, ','.join(l), work)
        call('fab -i %s -u ubuntu -P -H %s %s' % (your_key_path,','.join(l), work), shell=True)

def non_block_read(output):
    ''' even in a thread, a normal read with block until the buffer is full '''
    fd = output.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    try:
        return output.readline()
    except:
        return ''

def monitor(stdout, N, t):
    starting_time = time.time()
    counter = 0
    while True:
        output = non_block_read(stdout).strip()
        print output
        if 'synced transactions set' in output:
            counter += 1
            if counter >= N - t:
                break
    ending_time = time.time()
    print 'Latency from client scope:', ending_time - starting_time

def runProtocol():  # fast-path to run, assuming we already have the files ready
    callFabFromIPList(getIP(), 'runProtocol')

def runProtocolfromClient(client, key, hosts=None):
    if not hosts:
        callFabFromIPList(getIP(), 'runProtocolFromClient:%s,%s' % (client, key))
    else:
        callFabFromIPList(hosts, 'runProtocolFromClient:%s,%s' % (client, key))

def runEC2(Tx, N, t, n):  # run 4 in a row
    for i in range(1, n+1):
        runProtocolfromClient('"%d %d %d"' % (Tx, N, t), "~/%d_%d_%d.key" % (N, t, i))

def stopProtocol():
    callFabFromIPList(getIP(), 'stopProtocols')


#short-cuts

c = callFabFromIPList

def sk():
    c(getIP(), 'syncKeys')

def id():
    c(getIP(), 'install_dependencies')

def gp():
    c(getIP(), 'git_pull')

def rp(srp):
    c(getIP(), 'runProtocol:%s' % srp)

def killAll():
    c(getIP(), 'kill_All')

if  __name__ =='__main__':
  try: __IPYTHON__
  except NameError:
    parser = argparse.ArgumentParser()
    parser.add_argument('access_key', help='Access Key')
    parser.add_argument('secret_key', help='Secret Key')
    args = parser.parse_args()
    access_key = args.access_key
    secret_key = args.secret_key

    import IPython
    IPython.embed()
