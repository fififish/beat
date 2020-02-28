# Running BEAT0 on EC2

# Python dependencies:
    
    boto : http://boto.readthedocs.io/en/latest/boto_config_tut.html
    fabric (1.x): http://www.fabfile.org/installing-1.x.html
    scanf

# How to evaluate the protocol:

    Set up the account
    Open the port number 49500 by default for all the instances

    Under the EC2 folder, run 
        python utility.py [access key for AWS] [secret key for AWS]
        generate the keys for the network size you would like to run

    In the interactive interface, run the following commands sequentially
        Launch new instances 
            launch_new_instances([region],[N])
        Get the IPs
            ipAll()
        Synchronize the keys from local machine to remote instances
            c(getIP(),'syncKeys')
        Install the dependencies
            c(getIP(),'install_dependencies')
        Pull the code
            c(getIP(),'git_pull')
        Run the protocol
            c(getIP(),'runProtocol:N,t,B')

    After finishing the evaluation, run the following commands
        stop_all_instances([region])
        or
        terminate_all_instances([region])