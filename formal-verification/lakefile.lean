import Lake
open Lake DSL

package «formal-verification» {
  -- add package configuration options here
}

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git"@"26d0eab43f05db777d1cf31abd31d3a57954b2a9"

require ProvenZK from git
  "https://github.com/reilabs/proven-zk.git"@"4d6558d5b0032f243257a93759fb7ed73aa63f2c"

-- require ProvenZk from ".."/".."/"proven-zk"

lean_lib FormalVerification {
  moreLeanArgs := #["--tstack=65520", "-DmaxRecDepth=10000", "-DmaxHeartbeats=200000000"]
  -- add library configuration options here
}

@[default_target]
lean_exe «formal-verification» {
  moreLeanArgs := #["--tstack=65520", "-DmaxRecDepth=10000", "-DmaxHeartbeats=200000000"]
  root := `Main
}
