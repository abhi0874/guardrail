CREATE TABLE simulations (
 simulation_id TEXT PRIMARY KEY CHECK(length(simulation_id)=32),
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
 recipient TEXT NOT NULL CHECK(recipient IN ('ops-lab','docs-lab')),
 subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 120),
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 1500)
);
