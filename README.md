# Usage:

```
Execute the script as follows:

./ocp4healthcheck.sh 

usage: ocp4healthcheck.sh [--live | --must-gather] [--scanaudit] [--log]

Options:

--live | --must-gather  
          live         => analyze a running cluster in real-time
          must-gather  => analyze a must-gather
--scanaudit            => scan audit logs (only works with --live option for now)
--log                  => log the output to a file named ocp4healthcheck.log (created in the current working directory)
```

# Disclaimer:
Please review the LICENSE file. This script is free to distribute, open to contributions, and NOT SUPPORTED by Red Hat.
