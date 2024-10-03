import sys
import getopt
import subprocess
import json

def usage():
    print("usage: {} [--live | --must-gather] [--scanaudit] [--log]".format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)

options = ["live", "must-gather", "scanaudit", "log"]
params = sys.argv[1:]
try:
    opts, args = getopt.getopt(params, "", options)
except getopt.GetoptError as err:
    usage()

live = False
mustgather = False
scanaudit = False
log = False

for opt, arg in opts:
    if opt == "--live":
        live = True
    elif opt == "--must-gather":
        mustgather = True
    elif opt == "--scanaudit":
        scanaudit = True
    elif opt == "--log":
        log = True

if live and mustgather:
    usage()

if live:
    try:
        OCWHOAMI = subprocess.check_output(["oc", "whoami"], stderr=subprocess.DEVNULL, text=True).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Live option requires that OC login user context to be set. Ensure the user has cluster-admin permissions.", file=sys.stderr)
        sys.exit(1)
    else:
        if OCWHOAMI == "":
            print("Live option requires that OC login user context to be set. Ensure the user has cluster-admin permissions.", file=sys.stderr)
            sys.exit(1)
        else:
            cmd = "oc"
            print("Using this oc login user context:")
            server = subprocess.check_output(["oc", "whoami", "--show-server"], text=True).strip()
            user = subprocess.check_output(["oc", "whoami"], text=True).strip()
            print("API URL: {}   USER: {}".format(server, user))

if mustgather:
    try:
        omc_use_output = subprocess.check_output(["omc", "use"], stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Must-gather option requires configuring a must-gather to use with omc (https://github.com/gmeghnag/omc).", file=sys.stderr)
        sys.exit(1)
    else:
        if 'must-gather: ""' in omc_use_output:
            print("Must-gather option requires configuring a must-gather to use with omc (https://github.com/gmeghnag/omc).", file=sys.stderr)
            sys.exit(1)
        else:
            cmd = "omc"
            print("Using this omc must-gather report:")
            subprocess.run(["omc", "use"])

print("")
reply = input("Would you like to continue (Y/y) or set another user context for oc or omc (N/n)? ")
print("")
if reply.lower() not in ['y', 'yes']:
    sys.exit(0)

if log:
    sys.stdout = open("ocp4healthcheck.log", "w")
    sys.stderr = sys.stdout


try:
    OCPVER = subprocess.check_output([cmd, "get", "clusterversion", "-o=jsonpath={.items[*].status.desired.version}"], text=True).strip()
    OCPCLUSTERID = subprocess.check_output([cmd, "get", "clusterversion", "-o=jsonpath={.items[*].spec.clusterID}"], text=True).strip()
    print("\nCluster info:")
    print("OCP version   :  {}".format(OCPVER))
    print("OCP cluster ID:  {}".format(OCPCLUSTERID))
except subprocess.CalledProcessError as e:
    print("Failed to retrieve OCP cluster info:", e, file=sys.stderr)
    sys.exit(1)


# OCP node info
print("\nNode details:")


# OCP node info
print("\nNode details:\n")


try:
    # Retrieve information for master nodes
    master_info = subprocess.check_output(["oc", "get", "nodes"], text=True)
    master_nodes = [line.split()[0] for line in master_info.splitlines() if "master" in line]
    master_output = []
    total_master_cpu = 0
    for node in master_nodes:
        node_info = subprocess.check_output(["oc", "get", "node", node, "-o", "json"], text=True)
        node_info_dict = json.loads(node_info)
        cpu = node_info_dict['status']['capacity']['cpu']
        memory = node_info_dict['status']['capacity']['memory']
        master_output.append(f"{node}|{cpu}|{memory}|master")
        total_master_cpu += int(cpu)

    # Print master node information
    print("\nMaster nodes:")
    print("NAME|CPU|MEMORY|ROLES")
    for line in master_output:
        print(line)

    # Calculate total number of master nodes and total CPU
    total_master_nodes = len(master_nodes)
    print(f"Total Nodes:  {total_master_nodes}      Total CPU:  {total_master_cpu}")
except subprocess.CalledProcessError as e:
    print("Failed to retrieve master node info:", e, file=sys.stderr)
    exit(1)


try:
    # Retrieve information for worker nodes
    worker_info = subprocess.check_output(["oc", "get", "nodes"], text=True)
    worker_nodes = [line.split()[0] for line in worker_info.splitlines() if "worker" in line and "infra" not in line]
    worker_output = []
    total_worker_cpu = 0
    for node in worker_nodes:
        node_info = subprocess.check_output(["oc", "get", "node", node, "-o", "json"], text=True)
        node_info_dict = json.loads(node_info)
        cpu = node_info_dict['status']['capacity']['cpu']
        memory = node_info_dict['status']['capacity']['memory']
        worker_output.append(f"{node}|{cpu}|{memory}|worker")
        total_worker_cpu += int(cpu)

    # Print worker node information
    print("\nWorker nodes:")
    print("NAME|CPU|MEMORY|ROLES")
    for line in worker_output:
        print(line)

    # Calculate total number of worker nodes and total CPU
    total_worker_nodes = len(worker_nodes)
    print(f"Total Nodes:  {total_worker_nodes}      Total CPU:  {total_worker_cpu}")
except subprocess.CalledProcessError as e:
    print("Failed to retrieve worker node info:", e, file=sys.stderr)
    exit(1)

try:
    # Retrieve information for infra nodes
    infra_info = subprocess.check_output(["oc", "get", "nodes"], text=True)
    infra_nodes = [line.split()[0] for line in infra_info.splitlines() if "infra" in line]
    infra_output = []
    total_infra_cpu = 0
    for node in infra_nodes:
        node_info = subprocess.check_output(["oc", "get", "node", node, "-o", "json"], text=True)
        node_info_dict = json.loads(node_info)
        cpu = node_info_dict['status']['capacity']['cpu']
        memory = node_info_dict['status']['capacity']['memory']
        infra_output.append(f"{node}|{cpu}|{memory}|infra")
        total_infra_cpu += int(cpu)

    # Print infra node information
    print("\nInfra nodes:")
    print("NAME|CPU|MEMORY|ROLES")
    for line in infra_output:
        print(line)

    # Calculate total number of infra nodes and total CPU
    total_infra_nodes = len(infra_nodes)
    print(f"Total Nodes:  {total_infra_nodes}      Total CPU:  {total_infra_cpu}")
except subprocess.CalledProcessError as e:
    print("Failed to retrieve infra node info:", e, file=sys.stderr)
    exit(1)

print("\nSuggested Node Sizing:\n")
print("               ---- Master Node ----  ---- Worker Node ----  ---- Infra  Node ----")
print("Worker Count   vCPU  RAM-GB  Disk-GB  vCPU  RAM-GB  Disk-GB  vCPU   RAM-GB   Disk-GB")
print("============   ====  ======  =======  ====  ======  =======  =====  ======   =======")
print("<  25           4    16      120/500   2     8      120/500   4      16/ 24  120/500")
print(">= 25           8    32      120/500   4    16      120/500   8      32/ 48  120/500")
print(">= 120         16    64/ 96  120/500   8    32      120/500  16/48   64/ 96  120/500")
print(">= 252         16    96/128  120/500   8    32      120/500  32/48  128/192  120/500\n")
ETCDNS = "openshift-etcd"

# ETCD Health
print("\nETCD state:\n")
if live:
    try:
        ETCD = subprocess.check_output(["oc", "-n", ETCDNS, "get", "-l", "k8s-app=etcd", "pods", "-o", "name"], text=True).split()
        for pod in ETCD:
            print(f"\n-{pod}--------------------")
            subprocess.run(["oc", "exec", "-n", ETCDNS, pod, "-c", "etcdctl", "--", "etcdctl", "endpoint", "status", "-w", "table"])
    except subprocess.CalledProcessError as e:
        print("Error retrieving ETCD pod information:", e, file=sys.stderr)

if mustgather:
    try:
        subprocess.run(["oc", "etcd", "health"])
        subprocess.run(["oc", "etcd", "status"])
    except subprocess.CalledProcessError as e:
        print("Error checking ETCD health or status:", e, file=sys.stderr)


def print_status(description, grep_cmd):
    try:
        output = subprocess.check_output(grep_cmd, shell=True, text=True).strip()
        print(f"{description: <45}:", output)
    except subprocess.CalledProcessError:
        print(f"{description: <45}:", 0)


# ETCD log analysis
try:
    etcd_pods = subprocess.check_output([cmd, "-n", ETCDNS, "get", "pods", "-l", "etcd", "-o", "name"], text=True).split()
    for pod in etcd_pods:
        print("\nETCD log analysis:")
        print("")
        print(f"-[{pod}]--------------------")
        if live:
            start_timestamp = subprocess.check_output([cmd, "logs", "-c", "etcd", "-n", ETCDNS, pod, "--timestamps"], text=True).splitlines()[0].split()[0]
            end_timestamp = subprocess.check_output([cmd, "logs", "-c", "etcd", "-n", ETCDNS, pod, "--timestamps"], text=True).splitlines()[-1].split()[0]
            print(f"Log timestamp - Start               : {start_timestamp}")
            print(f"Log timestamp - End                 : {end_timestamp}")
        if mustgather:
            start_timestamp = subprocess.check_output([cmd, "logs", "-c", "etcd", "-n", ETCDNS, pod], text=True).splitlines()[0].split()[0]
            end_timestamp = subprocess.check_output([cmd, "logs", "-c", "etcd", "-n", ETCDNS, pod], text=True).splitlines()[-1].split()[0]
            print(f"Log timestamp - Start               : {start_timestamp}")
            print(f"Log timestamp - End                 : {end_timestamp}")
        
        grep_cmd = f"{cmd} logs -c etcd -n {ETCDNS} {pod} | grep -ic"
        print_status("local node might have slow network", f"{grep_cmd} 'local node might have slow network'")
        print_status("elected leader", f"{grep_cmd} 'elected leader'")
        print_status("leader changed", f"{grep_cmd} 'leader changed'")

        print_status("apply request took too long", f"{grep_cmd} 'apply request took too long'")
        print_status("lost leader", f"{grep_cmd} 'lost leader'")
        print_status("wal: sync duration", f"{grep_cmd} 'wal: sync duration'")
        print_status("slow fdatasync messages", f"{grep_cmd} 'slow fdatasync'")
        print_status("the clock difference against peer", f"{grep_cmd} 'the clock difference against peer'")
        print_status("lease not found", f"{grep_cmd} 'lease not found'")
        print_status("rafthttp: failed to read", f"{grep_cmd} 'rafthttp: failed to read'")
        print_status("leader failed to send out heartbeat on time", f"{grep_cmd} 'leader failed to send out heartbeat on time'")
        print_status("leader is overloaded likely from slow disk", f"{grep_cmd} 'leader is overloaded likely from slow disk'")
        print_status("lost the tcp streaming", f"{grep_cmd} 'lost the tcp streaming'")
        print_status("sending buffer is full (heartbeat)", f"{grep_cmd} 'sending buffer is full'")
        print_status("overloaded network (heartbeat)", f"{grep_cmd} 'overloaded network'")
        print_status("database space exceeded", f"{grep_cmd} 'database space exceeded'")
        print_status("Recent compaction", f"{grep_cmd} compaction | tail -8 | cut -d ',' -f6")
        if live:
            print("\nETCD object count:")
            etcd_obj_count_cmd = f"{cmd} exec -n {ETCDNS} {pod} -c etcdctl -n {ETCDNS} -- etcdctl get / --prefix --keys-only | sed '/^$/d' | cut -d/ -f3 | sort | uniq -c | sort -rn | head -14"
            subprocess.run(etcd_obj_count_cmd, shell=True)

            print("\nETCD objects [most events]:")
            etcd_obj_events_cmd = f"{cmd} exec -n {ETCDNS} {pod} -c etcdctl -n {ETCDNS} -- etcdctl get / --prefix --keys-only | grep event | cut -d/ -f3,4 | sort | uniq -c | sort -n --rev | head -10"
            subprocess.run(etcd_obj_events_cmd, shell=True)
except subprocess.CalledProcessError as e:
    print("Error:", e, file=sys.stderr)

def process_logs(role, path, service):
    print(f"\nAPI top consumers {service} on {role}s:\n")
    nodes = subprocess.check_output(["oc", "adm", "node-logs", "--role=" + role, "--path=" + path], text=True)
    logs = [line.split() for line in nodes.split('\n') if line.strip()]
    for node, logfile in logs:
        print(f"[ Processing NODE: {node}  LOGFILE: {logfile} ]")
        log_data = subprocess.check_output(["oc", "adm", "node-logs", node, "--path=" + path + "/" + logfile], text=True)
        usernames = [entry['user']['username'] for entry in json.loads(log_data) if 'user' in entry]
        username_counts = {username: usernames.count(username) for username in set(usernames)}
        sorted_usernames = sorted(username_counts.items(), key=lambda x: x[1], reverse=True)
        for username, count in sorted_usernames[:10]:
            print(f"{count} {username}")
        print()


if scanaudit:
    live = True  # Assuming live is set

    if live:
        process_logs("master", "kube-apiserver", "kube-apiserver")
        process_logs("master", "openshift-apiserver", "openshift-apiserver")


def print_monitoring_alerts(cmd, mustgather=False):
    if mustgather:
        # Print mustgather specific alerts
        alerts_data = subprocess.run([cmd, "prometheus", "alertrule", "-o", "json"], capture_output=True, text=True)
        if alerts_data.returncode == 0:
            alerts_json = json.loads(alerts_data.stdout)
            print("Alerts JSON:", alerts_json)  # Debugging statement
            for alert in alerts_json['data']:
                for alert_item in alert['alerts']:
                    if alert_item['state'] == 'firing':
                        alertname = alert_item['labels']['alertname']
                        message = alert_item['annotations']['message']
                        description = alert_item['annotations']['description']
                        print(f"{alertname}|{message}|{description}")

    if not mustgather:
        # Print live monitoring alerts
        alerts_data = subprocess.run([cmd, "-n", "openshift-monitoring", "exec", "-c", "prometheus", "prometheus-k8s-0", "--", "curl", "-s", "http://localhost:9090/api/v1/alerts"], capture_output=True, text=True)
        if alerts_data.returncode == 0:
            alerts_json = json.loads(alerts_data.stdout)
            print("Alerts JSON:", alerts_json)  # Debugging statement
            for data in alerts_json['data']:
                if 'data' in alerts_json and isinstance(alerts_json['data'], list):
                  for data in alerts_json['data']:
                    if data['state'] == 'firing':
                        alertname = data['labels']['alertname']
                        description = data['annotations']['description']
                        print(f"{alertname}|{description}")

def print_cluster_events(cmd):
    # Print cluster events (Non-Normal)
    events_output = subprocess.run([cmd, "get", "events", "-A"], capture_output=True, text=True)
    if events_output.returncode == 0:
        events = events_output.stdout.strip().split('\n')
        for event in events:
            if "Normal" not in event:
                print(event)


if live or mustgather:
    cmd = "oc"  # Update this with the actual command
    if live:
        print("\nMonitoring Alerts firing:")
        print_monitoring_alerts(cmd)
    if mustgather:
        print("\nMonitoring Alerts firing (mustgather):")
        print_monitoring_alerts(cmd, mustgather=True)

print("\nCluster Events (Non-Normal):")
print_cluster_events(cmd)
