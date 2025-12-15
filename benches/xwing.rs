#[allow(missing_docs)]
use criterion::{
    criterion_group, criterion_main, measurement::Measurement, BenchmarkGroup, Criterion,
};

use bedrock::xwing::*;

fn bench_keygen<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    group.bench_function("KeyGen Ml-Kem-512", |b| {
        b.iter(|| {
            let (_pk, _sk) = XwingScheme::X25519MlKem512.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen Ml-Kem-768", |b| {
        b.iter(|| {
            let (_pk, _sk) = XwingScheme::X25519MlKem768.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen Ml-Kem-1024", |b| {
        b.iter(|| {
            let (_pk, _sk) = XwingScheme::X25519MlKem1024.keypair().unwrap();
        });
    });

    group.bench_function("KeyGen McEliece348864", |b| {
        b.iter(|| {
            let (_pk, _sk) = XwingScheme::X25519McEliece348864.keypair().unwrap();
        });
    });
}

fn bench_encapsulate<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let (pk, _sk) = XwingScheme::X25519MlKem512.keypair().unwrap();
    group.bench_function("Encapsulate-Ml-Kem-512", |b| {
        b.iter(|| {
            let (_ct, _ss) = pk.encapsulate().unwrap();
        });
    });

    let (pk, _sk) = XwingScheme::X25519MlKem768.keypair().unwrap();
    group.bench_function("Encapsulate-Ml-Kem-768", |b| {
        b.iter(|| {
            let (_ct, _ss) = pk.encapsulate().unwrap();
        });
    });

    let (pk, _sk) = XwingScheme::X25519MlKem1024.keypair().unwrap();
    group.bench_function("Encapsulate-Ml-Kem-1024", |b| {
        b.iter(|| {
            let (_ct, _ss) = pk.encapsulate().unwrap();
        });
    });

    let (pk, _sk) = XwingScheme::X25519McEliece348864.keypair().unwrap();
    group.bench_function("Encapsulate-McEliece348864", |b| {
        b.iter(|| {
            let (_ct, _ss) = pk.encapsulate().unwrap();
        });
    });
}

fn bench_decapsulate<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let (pk, sk) = XwingScheme::X25519MlKem512.keypair().unwrap();
    let (ct, _ss) = pk.encapsulate().unwrap();
    let dk = sk.expand();
    group.bench_function("Decapsulate-Ml-Kem-512", |b| {
        b.iter(|| {
            let _ss1 = dk.decapsulate(&ct).unwrap();
        });
    });

    let (pk, sk) = XwingScheme::X25519MlKem768.keypair().unwrap();
    let (ct, _ss) = pk.encapsulate().unwrap();
    let dk = sk.expand();
    group.bench_function("Decapsulate-Ml-Kem-768", |b| {
        b.iter(|| {
            let _ss1 = dk.decapsulate(&ct).unwrap();
        });
    });

    let (pk, sk) = XwingScheme::X25519MlKem1024.keypair().unwrap();
    let (ct, _ss) = pk.encapsulate().unwrap();
    let dk = sk.expand();
    group.bench_function("Decapsulate-Ml-Kem-1024", |b| {
        b.iter(|| {
            let _ss1 = dk.decapsulate(&ct).unwrap();
        });
    });

    let (pk, sk) = XwingScheme::X25519McEliece348864.keypair().unwrap();
    let dk = sk.expand();
    let (ct, _ss) = pk.encapsulate().unwrap();
    group.bench_function("Decapsulate-McEliece348864", |b| {
        b.iter(|| {
            let _ss1 = dk.decapsulate(&ct).unwrap();
        });
    });
}

fn bench_xwing(c: &mut Criterion) {
    let mut group = c.benchmark_group("xwing");
    bench_keygen(&mut group);
    bench_encapsulate(&mut group);
    bench_decapsulate(&mut group);
    group.finish();
}

criterion_group!(benches, bench_xwing);
criterion_main!(benches);
