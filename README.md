# QModel

QModel is a live production post quantum model and dataset provenance tool for the Quantova network. It proves the register, dataset, weights, evaluation and release records of a machine learning model, and it lets any third party confirm that history without trusting the party that created it.

QModel proves records without disclosing them. Model internals, dataset contents and weights stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no private detail is ever published. A party is named only by a chain address.

## What it records

Each record is a signed envelope of one of five types.

1. register, an authority states the name, version and family of a model.
2. dataset, the authority records a dataset that the model was trained or evaluated on, along with its digest.
3. weights, the authority records a weights artifact of the model, along with its digest and parameter count.
4. evaluate, the authority records a benchmark score for the model.
5. release, the authority releases the model under a license and a disposition.

Every record is signed with FIPS 204 post quantum signatures by the authority it names, and each later record links to the one before it so the whole life of a model forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qmodel
```

## Use

```js
const qmodel = require('@quantovainc/qmodel');

const authority = qmodel.generateKey();
const model = qmodel.register({
  key: authority,
  name: 'atlas',
  version: '2.0.0',
  family: 'transformer',
  authorityLabel: 'Model Registry',
});

const anchored = await qmodel.anchor(model, { seed, index: 0, network: 'testnet' });
const result = await qmodel.verify(anchored[0], { type: 'register', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural person or an organisation. The authority is a chain address, and linking an address to a party is a separate attestation held off the chain.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
