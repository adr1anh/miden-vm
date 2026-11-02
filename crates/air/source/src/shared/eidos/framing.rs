//! Symbolic Eidos framing shared by semantic owners.

use core::array;

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::hash::eidos::Eidos;

/// Derives a symbolic packed initial CV from `(domain_tag, param0, param1, param2)`.
pub(crate) fn initial_cv_from_frame<E>(frame: [E; 4]) -> [E; 4]
where
    E: PrimeCharacteristicRing + From<Felt>,
{
    let base = Eidos::merkle_node_init_chaining_word().into_elements();
    array::from_fn(|idx| E::from(base[idx]) + frame[idx].clone())
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Word,
        deferred::{DEFERRED_AND_FRAME, EidosFrame, deferred_chunks_frame},
        program::{
            EnvNode, EnvironmentRoot, ImplementationRoot, LabelCommitment, Namespace, domain,
        },
    };
    use miden_crypto::hash::eidos::{EidosDomain, FeltSequence};

    use super::*;

    #[test]
    fn symbolic_initial_cv_matches_typed_frames() {
        for frame in [
            DEFERRED_AND_FRAME,
            deferred_chunks_frame(3),
            EidosFrame::new(DEFERRED_AND_FRAME.domain(), [1, 2, 3]),
        ] {
            assert_initial_cv(frame);
        }
    }

    #[test]
    fn registered_library_frames_match_core_commitments() {
        let label = LabelCommitment::new(word([1, 2, 3, 4]));
        let child = EnvironmentRoot::new(word([5, 6, 7, 8]));
        let implementation = ImplementationRoot::new(word([9, 10, 11, 12]));
        let right = EnvironmentRoot::new(word([17, 18, 19, 20]));

        assert_felt_sequence_frame(
            domain::ENV_ENVIRONMENT,
            &[label.into_word(), child.into_word()],
            EnvNode::Env { label, child }.commitment().unwrap().into_word(),
            [0x7ee4975d8da4550f, 0x7ba0da6db0b3b8eb, 0x5f88b4dc90bbccb7, 0x10a019e90f0acf6e],
        );
        assert_felt_sequence_frame(
            domain::ENV_MAST,
            &[label.into_word(), implementation.into_word()],
            EnvNode::Mast { label, implementation }.commitment().unwrap().into_word(),
            [0x2687b2281f2392c3, 0x64ce1d2a50a7f266, 0x78bcbc41290b68bb, 0x3d3dbe71acd140d3],
        );
        assert_felt_sequence_frame(
            domain::ENV_MERKLE,
            &[child.into_word(), right.into_word()],
            EnvNode::Merkle { left: child, right }.commitment().unwrap().into_word(),
            [0x1cdf4ce08689e5c9, 0x529cfa7528422cac, 0x5c8af375df4bbcaf, 0x6441dc497ffac51d],
        );

        let namespace = Namespace::new(label.into_word());
        let export_label = LabelCommitment::new(child.into_word());
        let payload = [namespace.into_word(), export_label.into_word()];
        assert_felt_sequence_frame(
            domain::ENV_INITIAL_NAMESPACE,
            &[],
            Namespace::initial().into_word(),
            [0x5af63cdc05e1732d, 0x7c441ffa1c95ee1f, 0x2e3dd14274ac5042, 0x09b0dc5782213a88],
        );
        assert_felt_sequence_frame(
            domain::ENV_NAMESPACE,
            &payload,
            namespace.child(export_label).into_word(),
            [0x68ace2d21f9b42de, 0x362d310e1d59e478, 0x3fe429f790e66da0, 0x3fda71606ac89b81],
        );
        assert_felt_sequence_frame(
            domain::ENV_PROCEDURE,
            &payload,
            namespace.procedure_key(export_label).into_word(),
            [0x14c540e058d350f2, 0x6854420e543dd8a5, 0x54dd6e100545038b, 0x40ac3ae85e48f3aa],
        );
    }

    #[test]
    fn registered_list_frames_use_the_variable_felt_length() {
        let children = [
            EnvironmentRoot::new(word([5, 6, 7, 8])),
            EnvironmentRoot::new(word([17, 18, 19, 20])),
            EnvironmentRoot::new(word([21, 22, 23, 24])),
            EnvironmentRoot::new(word([25, 26, 27, 28])),
        ];
        // The existing core fixtures cover empty input, odd padding, and complete blocks.
        let expected = [
            [0x3258664aa5f02db7, 0x0b248f02121839b7, 0x5db42a4793f149b6, 0x7a1ab3af0539329c],
            [0x10aa8a2a9b68db64, 0x7ab0ca2d9a4ddd0a, 0x629677b7ec77537a, 0x7a24bdc6c4b58a17],
            [0x2e9668b48fc2448c, 0x5bbecc9316abaf4b, 0x5a2c50e6211a9a2b, 0x1a65f7b74e8fe380],
            [0x26f406edba2bbeaa, 0x06587ad9f7efa059, 0x6e059110ad868cba, 0x5c21cd8396149d85],
            [0x79681507105576cb, 0x0530bef30e724fbf, 0x701764c784badd7c, 0x52bbed120d86e29a],
        ];
        let words = children.map(EnvironmentRoot::into_word);
        for (len, expected) in expected.into_iter().enumerate() {
            assert_felt_sequence_frame(
                domain::ENV_LIST,
                &words[..len],
                EnvNode::List(children[..len].to_vec()).commitment().unwrap().into_word(),
                expected,
            );
        }
    }

    fn assert_initial_cv(frame: EidosFrame) {
        assert_eq!(
            initial_cv_from_frame(frame.as_word().into_elements()),
            frame.initial_chaining_word().into_elements(),
        );
    }

    fn assert_felt_sequence_frame<D: EidosDomain<Encoding = FeltSequence>>(
        domain: D,
        payload: &[Word],
        core_commitment: Word,
        expected: [u64; 4],
    ) {
        let elements = Word::words_as_elements(payload);
        let felt_len = u32::try_from(elements.len()).unwrap();
        assert_initial_cv(EidosFrame::for_domain(domain, [felt_len, 0, 0]));
        assert_eq!(Eidos::hash_elements_in_domain(elements, domain), core_commitment);
        // Selected hashes are frozen in core/tests/fixtures/librarytree-vectors.txt.
        assert_eq!(core_commitment, word(expected));
    }

    fn word(values: [u64; 4]) -> Word {
        Word::new(values.map(Felt::new_unchecked))
    }
}
