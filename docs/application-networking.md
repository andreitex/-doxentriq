# Application network address reservations

IT selects `app_network_pool` during installation. The broker receives the same
value as `APP_NETWORK_POOL`. There is no guessed default: supply a canonical
RFC1918 IPv4 network between `/16` and `/24` that your LAN, VPN, cloud networks,
Docker networks and planned routes do not use. The installer checks the current
host interfaces and all IPv4 routing tables before accepting a fresh pool.
Ordinary administrators do not choose subnet addresses in chat.

Each new application resource receives a private Docker bridge with a reserved
`/26`. Production and preview resources have separate reservations. Addresses
are offsets from that subnet's network address:

| Offset | Purpose |
|---|---|
| `.1` | Bridge gateway |
| `.2` | MySQL |
| `.3` | Redis |
| `.4` | RabbitMQ |
| `.5` | Caddy |
| `.6` | Control API, attached when directory authorization is enabled |
| `.32` through `.63` | Upper `/27` allocated to Docker's dynamic range, subject to Docker's reserved-address rules |

The offsets are relative: in a subnet ending in `.64/26`, MySQL uses `.66`,
and the dynamic range begins at `.96/27`. Company service addresses are passed
explicitly to Docker outside its dynamic range. Application host mappings
require independent container and network readback, including the persisted
static IPAM request. Docker preserves an explicitly requested address across
container stop/start; if it is unavailable, startup fails instead of silently
choosing another address. [Docker network connection behavior](https://docs.docker.com/reference/cli/docker/network/connect/#network-implications-of-stopping-pausing-or-restarting-containers).

The sole installation broker serializes allocation and saves each reservation in
encrypted resource state before creating a network. Allocation checks retained
reservations, every inspected Docker subnet and a fresh authenticated host
network snapshot. Ordinary default routes are ignored; broad VPN routes such
as `/1` and policy routing tables remain conflicts. During verification, only
the independently verified application's own bridge routes inside its reserved
subnet are excluded. Unavailable, stale, oversized or changing observations
block provisioning.

Resource inventory waits for active encrypted resource writes; abandoned
temporary files remain a blocking condition for IT review. Network creation and
service connections have retained intents. A connection intent binds the exact
container ID to its reserved service, network and address, and records successful
independent readback. After an
interruption, the broker may accept an independently verified exact result;
it does not blindly repeat an action whose outcome is unknown. Changed network
ownership, IDs, address ranges or static service addresses require IT review.
The current bounded inventory supports at most 512 Docker networks and 512
resource records; a smaller chosen pool can exhaust earlier.

## Existing installations and remaining qualification

Existing dynamic application networks are preserved. This implementation does
not disconnect, adopt, rename or migrate them automatically. Provisioning or
changing connections for a legacy resource requires a separately reviewed IT
migration. Changing the configured pool also requires migration review.
Database accounts, grants and passwords are not rewritten to compensate for
address changes.

This change covers the five company service aliases listed above. Connector
sidecars still use dynamic addresses; connector host mappings need separate
recovery work. Replacing a company service container after a recorded attachment
also requires IT review; automatic service recreation is not qualified by this
change. Company Compose networks that use Docker DNS are outside this app
address reservation mechanism.

Automated tests cover pool conflicts, concurrent encrypted reservations,
authenticated host observation, static attachment readback, interrupted actions,
and rejection of legacy or altered connections. Fake Docker results in these
tests do not establish real daemon, full installer or reboot compatibility.
The Debian/Rocky clean installation and reboot acceptance matrix remains a
separate qualification requirement.
