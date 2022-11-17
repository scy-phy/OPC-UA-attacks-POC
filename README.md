Security Analysis of Vendor Implementations of the OPC UA Protocol for Industrial Control Systems
=======

## In proceedings of CPS & IoT Security and Privacy Workshop (CPSIoTSec2022) co-located with ACM CCS 2022

When using the code from this repository please cite our work as follows:
```
@InProceedings{erba22OPCUA,
  author       = "Erba, Alessandro and Müller, Anne and Tippenhauer, Nils Ole",
  title        = {Security Analysis of Vendor Implementations of the OPC UA Protocol for Industrial Control Systems},
  booktitle    = "Proceedings of the 4th Workshop on CPS \& IoT Security and Privacy (CPSIoTSec '22)",
  year         = "2022",
  month        = NOV,
  address      = "Los Angeles, CA, USA",
  publisher    = "ACM",
  doi          = "10.1145/3560826.3563380"
}
``` 

### Presented at Black Hat Europe 2021
## Resting on Feet of Clay: Securely Bootstrapping OPC UA Deployments
### Alessandro Erba, Anne Müller, Nils Ole Tippenhauer
### CISPA Helmholtz Center for Information Security

Requirements:

- Python OPC UA https://github.com/FreeOpcUa/python-opcua
- OpenSSL
- Python3

Usage:
`./framework.py`

options:
- `-h help`
- `-a rogue_client`
- `-a rogue_server`
- `-a middleperson`
