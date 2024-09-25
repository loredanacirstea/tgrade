# upgrades

## manual upgrade module

This can be used for upgrades that cannot be scheduled by governance and are difficult to implement as store migrations.

* create ./tgrade/data/upgrade-info.json
```
{"name":"v4","height":11470249}
```

* (optional) reset ALL the validators private state (danger!)
If the chain halted due to a consensus failure and nodes have already signed in a consensus round, if we need to change the validator composition for example, we will want to reset each validator's private state. In this case, all validators must reset their state.
```
node0/tgrade/data/priv_validator_state.json
{
  "height": "11470249",
  "round": 0,
  "step": 0,
  "signature": "",
  "signbytes": ""
}
```

* after upgrade, remove `upgrade-info.json`!
