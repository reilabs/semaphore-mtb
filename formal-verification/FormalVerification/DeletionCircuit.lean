import ProvenZk.Binary
import ProvenZk.Hash
import ProvenZk.Merkle
import ProvenZk.Ext.Vector

import FormalVerification
import FormalVerification.SemanticEquivalence

open SemaphoreMTB (F Order)

variable [Fact (Nat.Prime Order)]

open SemaphoreMTB renaming VerifyProof_31_30 → gVerifyProof
open SemaphoreMTB renaming DeletionRound_30_30 → gDeletionRound
open SemaphoreMTB renaming DeletionProof_4_4_30_4_4_30 → gDeletionProof

set_option pp.coercions false

def TreeDelete [Fact (perfect_hash poseidon₂)]
  (Tree : MerkleTree F poseidon₂ D) (Skip : Bit) (Path : Vector F D) (Item : F) (Proof : Vector F D) (k : F → Prop): Prop :=
  match Skip with
  | Bit.zero => 
      MerkleTree.item_at Tree (Dir.create_dir_vec Path).reverse = Item ∧
      MerkleTree.proof Tree (Dir.create_dir_vec Path).reverse = Proof.reverse ∧
      k (MerkleTree.set Tree (Dir.create_dir_vec Path).reverse 0).root
  | Bit.one => k Tree.root

def TreeDeletePrep [Fact (perfect_hash poseidon₂)]
  (Tree : MerkleTree F poseidon₂ D) (Index Item : F) (Proof : Vector F D) (k : F → Prop): Prop :=
  ∃path, nat_to_bits_le (D+1) Index.val = some path ∧
  TreeDelete Tree (path.last) (Vector.map Bit.toZMod path.dropLast) Item Proof k

theorem deletion_round_uncps [Fact (perfect_hash poseidon₂)] (Tree : MerkleTree F poseidon₂ D) (Skip : Bit) (Path : Vector F D) (Item: F) (Proof : Vector F D) (k : F → Prop):
  deletion_round Tree.root Skip Path Item Proof k ↔
  TreeDelete Tree Skip Path Item Proof k := by
  unfold deletion_round
  unfold TreeDelete
  split
  . simp
    simp [MerkleTree.recover_tail_equals_recover_reverse]
    rw [<-MerkleTree.recover_equivalence]
    simp [and_assoc]
    intro hitem_at hproof
    rw [MerkleTree.proof_insert_invariant (ix := (Vector.reverse (Dir.create_dir_vec Path))) (tree := Tree) (old := Item) (new := (0:F)) (proof := Vector.reverse Proof)]
    rw [<-MerkleTree.recover_equivalence]
    apply And.intro
    rw [hitem_at]
    rw [hproof]
  . simp

theorem deletion_round_prep_uncps [Fact (perfect_hash poseidon₂)]
  (Tree : MerkleTree F poseidon₂ D) (Index Item : F) (Proof : Vector F D) (k : F → Prop) : 
  deletion_round_prep Tree.root Index Item Proof k ↔
  TreeDeletePrep Tree Index Item Proof k := by
  unfold deletion_round_prep
  unfold TreeDeletePrep
  simp [deletion_round_uncps]
  apply Iff.intro
  . rintro ⟨ixbin, _⟩
    casesm* (_ ∧ _)
    have : nat_to_bits_le (D+1) Index.val = some (vector_zmod_to_bit ixbin) := by
      apply recover_binary_zmod'_to_bits_le
      . simp
      . assumption
      . rename_i h _ _ _; simp[h]
    rw [this]
    simp [←Dir.create_dir_vec_bit]
    simp [vector_zmod_to_bit_last]
    rw [vector_zmod_to_bit_dropLast]
    assumption
    assumption
  . rintro ⟨ixbin, h⟩
    casesm* (_ ∧ _)
    rename_i l r
    let t : Vector F (D+1) := (Vector.map Bit.toZMod ixbin)
    refine ⟨t, ?_⟩
    refine ⟨?_, ⟨?_, ⟨?_, ?_⟩⟩⟩
    . apply recover_binary_of_to_bits
      simp [l]
    . apply vector_binary_of_bit_to_zmod
    . simp [Bit.toZMod, is_bit, Vector.last]
      split
      simp
      simp
    . simp
      simp [dropLast_symm] at r
      have : (Vector.last ixbin) = zmod_to_bit (Vector.last (Vector.map (fun i => @Bit.toZMod Order i) ixbin)) := by
        rw [<-vector_zmod_to_bit_last]
        simp [vector_bit_to_zmod_to_bit]
      rw [<-this]
      assumption