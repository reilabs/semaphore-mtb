import FormalVerification
import FormalVerification.BinaryReps.Basic
import FormalVerification.BinaryReps.SemanticEquivalence
import FormalVerification.Keccak.SemanticEquivalence
import ProvenZk.Gates

open SemaphoreMTB (F Order)

variable [Fact (Nat.Prime Order)]

def RC : Vector (Fin (2 ^ 64)) 24 := vec![0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

def RCBits : SubVector (Vector F 64) 24 (allIxes is_bit):=
  SubVector.lift (Vector.map (fun x => SubVector.lift (Vector.map embedBit (fin_to_bits_le x))) RC)

def ofFnGet (v : Vector F d) : Vector F d := Vector.ofFn fun i => v[i.val]'i.prop
instance : HAppend (Vector α d₁) (Vector α d₂) (Vector α (d₁ + d₂)) := ⟨Vector.append⟩



-- theorem allIxes_append : (SubVector α d n).val ++


def DeletionMbuCircuit_4_4_30_4_4_30_Fold (InputHash: F) (DeletionIndices: Vector F 4) (PreRoot: F) (PostRoot: F) (IdComms: Vector F 4) (MerkleProofs: Vector (Vector F 30) 4): Prop :=
    SemaphoreMTB.ToReducedBigEndian_32 DeletionIndices[0] fun gate_0 =>
    SemaphoreMTB.ToReducedBigEndian_32 DeletionIndices[1] fun gate_1 =>
    SemaphoreMTB.ToReducedBigEndian_32 DeletionIndices[2] fun gate_2 =>
    SemaphoreMTB.ToReducedBigEndian_32 DeletionIndices[3] fun gate_3 =>
    SemaphoreMTB.ToReducedBigEndian_256 PreRoot fun gate_4 =>
    SemaphoreMTB.ToReducedBigEndian_256 PostRoot fun gate_5 =>
    SemaphoreMTB.KeccakGadget_640_64_24_640_256_24_1088_1
      (ofFnGet gate_0 ++ ofFnGet gate_1 ++ ofFnGet gate_2 ++ ofFnGet gate_3 ++ ofFnGet gate_4 ++ ofFnGet gate_5) RCBits.val fun gate_6 =>
    SemaphoreMTB.FromBinaryBigEndian_256 gate_6 fun gate_7 =>
    Gates.eq InputHash gate_7 ∧
    SemaphoreMTB.DeletionProof_4_4_30_4_4_30 DeletionIndices PreRoot IdComms MerkleProofs fun gate_9 =>
    Gates.eq gate_9 PostRoot ∧
    True

theorem DeletionCircuit_folded {InputHash PreRoot PostRoot : F} {DeletionIndices IdComms : Vector F 4} {MerkleProofs: Vector (Vector F 30) 4}:
  SemaphoreMTB.DeletionMbuCircuit_4_4_30_4_4_30 InputHash DeletionIndices PreRoot PostRoot IdComms MerkleProofs =
  DeletionMbuCircuit_4_4_30_4_4_30_Fold InputHash DeletionIndices PreRoot PostRoot IdComms MerkleProofs := by rfl

@[simp]
theorem ofFnGet_id : ofFnGet v = v := by simp [ofFnGet, GetElem.getElem]

theorem allIxes_append : allIxes prop (v₁ ++ v₂) ↔ allIxes prop v₁ ∧ allIxes prop v₂ := by
  sorry

theorem SubVector_append {v₁ : Vector α d₁} {prop₁ : allIxes prop v₁ } {v₂ : Vector α d₂} {prop₂ : allIxes prop v₂}:
  (Subtype.mk v₁ prop₁).val ++ (Subtype.mk v₂ prop₂).val =
  (Subtype.mk (v₁ ++ v₂) (allIxes_append.mpr ⟨prop₁, prop₂⟩)).val := by eq_refl

theorem InputHash_deterministic :
  SemaphoreMTB.DeletionMbuCircuit_4_4_30_4_4_30 InputHash₁ DeletionIndices PreRoot PostRoot IdComms MerkleProofs₁ ∧
  SemaphoreMTB.DeletionMbuCircuit_4_4_30_4_4_30 InputHash₂ DeletionIndices PreRoot PostRoot IdComms MerkleProofs₂ →
  InputHash₁ = InputHash₂ := by
  repeat rw [DeletionCircuit_folded]
  unfold DeletionMbuCircuit_4_4_30_4_4_30_Fold
  intro ⟨h₁, h₂⟩
  repeat have h₁ := constant_domain_rw ToReducedBigEndian_32_constant ToReducedBigEndian_32_domain h₁
  repeat have h₂ := constant_domain_rw ToReducedBigEndian_32_constant ToReducedBigEndian_32_domain h₂
  simp_rw [ofFnGet_id] at h₁ h₂
  simp_rw [(ToReducedBigEndian_256_constant _).equiv] at h₁ h₂
  simp_rw [SubVector_append] at h₁ h₂
  simp_rw [(KeccakGadget_640_64_24_640_256_24_1088_1_constant _ _).equiv] at h₁ h₂
  simp_rw [(FromBinaryBigEndian_256_constant _).equiv] at h₁ h₂
  rcases h₁ with ⟨h₁, _⟩
  rcases h₂ with ⟨h₂, _⟩
  subst h₁
  subst h₂
  eq_refl

theorem InputHash_injective :
  SemaphoreMTB.DeletionMbuCircuit_4_4_30_4_4_30 InputHash DeletionIndices₁ PreRoot₁ PostRoot₁ IdComms₁ MerkleProofs₁ ∧
  SemaphoreMTB.DeletionMbuCircuit_4_4_30_4_4_30 InputHash DeletionIndices₂ PreRoot₂ PostRoot₂ IdComms₂ MerkleProofs₂ →
  DeletionIndices₁ = DeletionIndices₂ ∧ PreRoot₁ = PreRoot₂ ∧ PostRoot₁ = PostRoot₂ := by sorry
