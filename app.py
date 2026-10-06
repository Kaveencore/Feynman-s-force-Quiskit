import random
import time

import joblib
import pandas as pd
import streamlit as st
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

st.set_page_config(
    page_title="Quantum-Secure Network Demo",
    page_icon="🔐",
    layout="wide",
)

st.title("Quantum-Secure Biomedical Network Monitor")
st.caption(
    "Educational demo: NSL-KDD network classification "
    "combined with a simulated BB84 channel."
)

column_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

@st.cache_resource
def load_classifier():
    return joblib.load("nsl_kdd_model.joblib")

@st.cache_data
def load_test_data():
    return pd.read_csv(
        "KDDTest+.txt",
        header=None,
        names=column_names
    )

classical_ai = load_classifier()
test_df = load_test_data()


@st.cache_data(show_spinner="Running the BB84 simulation...")
def run_bb84(scenario, number_of_qubits=512):
    rng = random.Random(7)

    alice_bits = [
        rng.randint(0, 1)
        for _ in range(number_of_qubits)
    ]
    alice_bases = [
        rng.choice(["Z", "X"])
        for _ in range(number_of_qubits)
    ]
    bob_bases = [
        rng.choice(["Z", "X"])
        for _ in range(number_of_qubits)
    ]

    noise_rng = random.Random(99)
    eve_rng = random.Random(123)
    eve_bases = [
        eve_rng.choice(["Z", "X"])
        for _ in range(number_of_qubits)
    ]

    circuits = []

    for i in range(number_of_qubits):
        circuit = QuantumCircuit(1, 1)

        # Alice prepares a bit using her chosen basis
        if alice_bits[i] == 1:
            circuit.x(0)
        if alice_bases[i] == "X":
            circuit.h(0)

        if scenario == "10% bit-flip noise":
            # Sometimes the channel flips the qubit
            if noise_rng.random() < 0.10:
                circuit.x(0)

        elif scenario == "Eve intercept-resend":
            # Eve measures in her own randomly chosen basis
            if eve_bases[i] == "X":
                circuit.h(0)
            circuit.measure(0, 0)

            # Eve resends a qubit prepared from her measurement
            circuit.reset(0)
            with circuit.if_test((circuit.clbits[0], 1)):
                circuit.x(0)
            if eve_bases[i] == "X":
                circuit.h(0)

        # Bob measures in his randomly chosen basis
        if bob_bases[i] == "X":
            circuit.h(0)
        circuit.measure(0, 0)
        circuits.append(circuit)

    simulator = AerSimulator()
    result = simulator.run(
        circuits,
        shots=1,
        memory=True
    ).result()

    bob_bits = [
        int(result.get_memory(i)[0])
        for i in range(number_of_qubits)
    ]

    # Sifting: keep positions where Alice and Bob chose the same basis
    sifted = [
        i for i in range(number_of_qubits)
        if alice_bases[i] == bob_bases[i]
    ]

    errors = sum(
        alice_bits[i] != bob_bits[i]
        for i in sifted
    )
    qber = errors / len(sifted)

    # Keep a small, readable trace for the dashboard walkthrough
    preview_size = min(12, number_of_qubits)
    trace = pd.DataFrame({
        "Slot": range(1, preview_size + 1),
        "Alice bit": alice_bits[:preview_size],
        "Alice basis": alice_bases[:preview_size],
        "Bob basis": bob_bases[:preview_size],
        "Bob measured bit": bob_bits[:preview_size],
        "Kept after sifting": [
            "Yes" if alice_bases[i] == bob_bases[i] else "No"
            for i in range(preview_size)
        ],
        "Bits agree": [
            "—" if alice_bases[i] != bob_bases[i]
            else ("Yes" if alice_bits[i] == bob_bits[i] else "No")
            for i in range(preview_size)
        ],
    })

    return qber, len(sifted), errors, trace

def final_decision(network_prediction, qber_value):
    # These are demonstration thresholds, not real-world security standards
    if network_prediction == 1:
        return "REJECT"
    if qber_value >= 0.10:
        return "REJECT"
    if qber_value >= 0.03:
        return "MONITOR"
    return "ACCEPT"


st.divider()
st.header("Run the live demo")

left, right = st.columns(2)

with left:
    st.subheader("1. Choose a network record")
    record_group = st.selectbox(
        "Example record type",
        ["Normal record", "Attack record"]
    )

    if record_group == "Normal record":
        records = test_df[test_df["label"] == "normal"]
    else:
        records = test_df[test_df["label"] != "normal"]

    record_number = st.slider(
        "Choose an example",
        min_value=1,
        max_value=min(20, len(records)),
        value=1
    )

    record_index = records.index[record_number - 1]
    record = test_df.loc[record_index]
    record_features = test_df.drop(
        columns=["label", "difficulty"]
    ).loc[[record_index]]

    st.write("Actual dataset label:", record["label"])
    st.dataframe(
        record_features[
        ["duration", "protocol_type", "service", "flag",
             "src_bytes", "dst_bytes"]
        ],
        hide_index=True,
        width="stretch",
        alt="Selected NSL-KDD network record features",
    )

with right:
    st.subheader("2. Choose a BB84 scenario")
    selected_scenario = st.selectbox(
        "Quantum channel condition",
        [
            "Clear channel",
            "10% bit-flip noise",
            "Eve intercept-resend"
        ]
    )
    st.write(
        "The app will compare all three scenarios and use your selection "
        "for the final decision."
    )

if st.button("Run security analysis", type="primary"):
    scenario_names = [
        "Clear channel",
        "10% bit-flip noise",
        "Eve intercept-resend"
    ]

    channel_explanations = {
        "Clear channel": "No extra disturbance is added to the qubits.",
        "10% bit-flip noise": (
            "The channel randomly applies an X gate to 10% of qubits."
        ),
        "Eve intercept-resend": (
            "Eve measures each qubit in a random basis, then resends a qubit."
        ),
    }

    with st.status("Walking through the protocol...", expanded=True) as status:
        st.write(
            "**Step 1 — Alice prepares qubits.** She randomly chooses a bit "
            "and a Z or X basis for each transmission."
        )
        time.sleep(0.8)

        st.write(
            f"**Step 2 — Channel condition.** {channel_explanations[selected_scenario]}"
        )
        time.sleep(0.8)

        st.write(
            "**Step 3 — Bob measures.** Qiskit simulates the qubits, and Bob "
            "measures each one in his independently chosen basis."
        )

        network_prediction = int(
            classical_ai.predict(record_features)[0]
        )

        selected_result = run_bb84(selected_scenario)
        time.sleep(0.8)

        st.write(
            "**Step 4 — Sifting.** Alice and Bob keep only positions where "
            "their bases matched. Here are the first 12 simulated positions:"
        )
        st.dataframe(
            selected_result[3],
            hide_index=True,
            width="stretch",
            alt="Sample qubit transmissions showing bases, measurements, and sifting",
        )
        time.sleep(0.8)

        st.write(
            "**Step 5 — QBER.** For this educational simulation, the simulator "
            "compares all sifted bits and counts their errors."
        )
        st.write(
            f"Sifted bits: **{selected_result[1]}** · "
            f"Errors: **{selected_result[2]}** · "
            f"QBER: **{selected_result[0]:.1%}**"
        )

        st.write("Repeating the simulation for the other channel conditions...")
        qkd_results = {selected_scenario: selected_result}
        for name in scenario_names:
            if name != selected_scenario:
                qkd_results[name] = run_bb84(name)

        selected_qber = qkd_results[selected_scenario][0]
        decision = final_decision(network_prediction, selected_qber)
        prediction_name = (
            "ATTACK" if network_prediction == 1 else "NORMAL"
        )
        st.write(
            "**Step 6 — Combined decision.** The network model predicts "
            f"**{prediction_name}**; the selected QBER is "
            f"**{selected_qber:.1%}**; the demo policy returns **{decision}**."
        )
        st.write(
            "This demonstration stops at QBER. It does not perform final key "
            "distillation or encrypt a message."
        )
        time.sleep(0.8)

        status.update(
            label="Protocol walkthrough complete",
            state="complete",
            expanded=True,
        )

    st.divider()
    st.subheader("Results")

    metric1, metric2, metric3 = st.columns(3)
    metric1.metric("Network model", prediction_name)
    metric2.metric(
        f"QBER — {selected_scenario}",
        f"{selected_qber:.1%}"
    )
    metric3.metric("Final decision", decision)

    if decision == "ACCEPT":
        st.success("The demo policy accepts this connection.")
    elif decision == "MONITOR":
        st.warning("The demo policy flags this connection for monitoring.")
    else:
        st.error("The demo policy rejects this connection.")

    st.caption(
        "This is an educational simulation. Its decision thresholds are "
        "demonstration settings, not production security rules."
    )

    # Compare the QBER and decision for all three channel conditions
    qber_values = [qkd_results[name][0] for name in scenario_names]
    decisions = [
        final_decision(network_prediction, value)
        for value in qber_values
    ]

    comparison = pd.DataFrame({
        "BB84 scenario": scenario_names,
        "QBER": [f"{value:.1%}" for value in qber_values],
        "Final decision": decisions
    })

    st.subheader("Scenario comparison")
    st.dataframe(
        comparison,
        hide_index=True,
        width="stretch",
        alt="QBER and decision comparison for three BB84 channel conditions",
    )

    chart_data = pd.DataFrame({
        "Scenario": scenario_names,
        "QBER": qber_values,
    })
    st.bar_chart(
        chart_data,
        x="Scenario",
        y="QBER",
        alt="QBER comparison across clear, noisy, and eavesdropped channels",
    )
