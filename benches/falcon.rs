#[allow(missing_docs)]
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use tectonic_bedrock::falcon::FalconScheme;

fn bench_falcon_sign_and_verify(c: &mut Criterion) {
    let scheme_dsa = FalconScheme::Dsa512;
    let (_vk_dsa, sk_dsa) = scheme_dsa.keypair().expect("keygen failed");

    let scheme_eth = FalconScheme::Ethereum;
    let (_vk_eth, sk_eth) = scheme_eth.keypair().expect("eth keygen failed");

    let message = black_box(b"this is a typical ethereum transaction hash payload 1234567890");

    let mut group = c.benchmark_group("falcon_sign_verify");

    group.bench_function("falcon_dsa512_sign", |b| {
        b.iter(|| scheme_dsa.sign(message, &sk_dsa).unwrap())
    });

    group.bench_function("falcon_dsa512_verify", |b| {
        let sig = scheme_dsa.sign(message, &sk_dsa).unwrap();
        b.iter(|| scheme_dsa.verify(message, &sig, &_vk_dsa).unwrap())
    });

    group.bench_function("ethfalcon_sign", |b| {
        b.iter(|| scheme_eth.sign(message, &sk_eth).unwrap())
    });

    group.bench_function("ethfalcon_verify", |b| {
        let sig = scheme_eth.sign(message, &sk_eth).unwrap();
        b.iter(|| scheme_eth.verify(message, &sig, &_vk_eth).unwrap())
    });

    group.finish();
}

criterion_group!(benches, bench_falcon_sign_and_verify);
criterion_main!(benches);
