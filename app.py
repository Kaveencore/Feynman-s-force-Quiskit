"""Educational Streamlit demo: NSL-KDD classification and simulated BB84."""

import hashlib
import os
import random
import time

import joblib
import pandas as pd
import streamlit as st
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


st.set_page_config(
    page_title="Quantum-Secure Hospital Link",
    page_icon="🩺",
    layout="wide",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Space Grotesk', sans-serif; }
    .stApp { background: radial-gradient(ellipse at 8% 0%, #252255 0, #101321 42%, #101321 100%); }
    h1 { letter-spacing: -1.8px; }
    .hero { padding: 1.25rem 1.5rem; border: 1px solid #4b4b75; border-radius: 20px;
      background: linear-gradient(115deg, #262552 0%, #272343 48%, #163b46 100%); }
    .hero-tag { color: #9fffe0; font: 500 .8rem 'DM Mono', monospace; letter-spacing: 2px; }
    .step-card { padding: 1rem 1.1rem; border: 1px solid #41435c; border-radius: 16px;
      background: #1a1d2b; min-height: 115px; }
    .step-card b { color: #ff7bcb; }
    .note { color: #bac2d6; font-size: .9rem; }
    .storyboard { position: relative; overflow: hidden; min-height: 245px; margin: .8rem 0 1rem;
      border: 1px solid #615b91; border-radius: 18px;
      background: radial-gradient(circle at 50% 46%, #313052 0, #171a2b 65%); }
    .story-title { padding: 12px 16px 0; color: #a8ffe9; font-weight: 700; }
    .story-actors { position: absolute; inset: 52px 4% auto; z-index: 2;
      display: grid; grid-template-columns: 1fr 1fr 1fr; align-items: center; text-align: center; }
    .story-actor { justify-self: center; width: min(170px, 92%); padding: 10px 7px;
      border: 1px solid #555775; border-radius: 16px; background: #22263a; box-shadow: 0 8px 24px #080a14a8; }
    .story-emoji { font-size: 40px; line-height: 1.15; }
    .story-name { color: #f5f4ff; font-weight: 700; }
    .story-sub { color: #afb9d2; font-size: 12px; }
    .story-line { position: absolute; top: 58%; left: 12%; right: 12%; height: 3px;
      background: linear-gradient(90deg, #63edff, #b078ff, #ff76c8); box-shadow: 0 0 12px #a278ff; }
    .story-qubit { position: absolute; z-index: 4; top: calc(58% - 16px); left: 12%; width: 32px; height: 32px;
      display: grid; place-items: center; color: #141629; font-size: 18px; font-weight: 900;
      border-radius: 50%; background: #9fffe6; box-shadow: 0 0 12px #8effea, 0 0 30px #b078ff;
      animation: qubit-travel 4.8s ease-in-out infinite alternate; }
    .storyboard.has-hacker .story-qubit { animation-name: qubit-intercept; }
    .storyboard.has-hacker .hacker-actor { border-color: #ff648b; animation: hacker-pulse 1.4s ease-in-out infinite alternate; }
    .storyboard.has-noise .story-line { background: repeating-linear-gradient(90deg, #ffcf70 0 14px, #ff628d 14px 22px); }
    .storyboard.has-noise .story-qubit { animation-duration: .45s; }
    .story-caption { position: absolute; bottom: 9px; width: 100%; text-align: center;
      color: #c2c9dc; font: 12px 'DM Mono', monospace; }
    @keyframes qubit-travel { from { left: 12%; transform: rotate(0) scale(1); }
      to { left: 84%; transform: rotate(360deg) scale(1.15); } }
    @keyframes qubit-intercept { 0% { left: 12%; transform: scale(1); }
      38% { left: 43%; transform: scale(1.1); } 50% { left: 49%; transform: scale(.72); }
      62% { left: 55%; transform: scale(1.2); } 100% { left: 84%; transform: scale(1); } }
    @keyframes hacker-pulse { from { box-shadow: 0 0 0 #ff648b; }
      to { box-shadow: 0 0 22px #ff648b88; } }
    div[data-testid="stMetric"] { background: #1c2030; border: 1px solid #393d55;
      padding: 13px 16px; border-radius: 14px; }
    div.stButton > button[kind="primaryFormSubmit"], div.stButton > button[kind="primary"] {
      background: linear-gradient(90deg, #ff5e9c, #a777ff); border: 0; color: white;
      border-radius: 12px; font-weight: 700; }
    code, pre { font-family: 'DM Mono', monospace !important; }
    </style>
    <div class="hero">
      <div class="hero-tag">🩺 HOSPITAL → DOCTOR · QUANTUM KEY DEMO</div>
      <h1>Can the Doctor receive this message safely?</h1>
      <p class="note">A playful, educational simulation combining NSL-KDD traffic classification,
      a Qiskit BB84 key-exchange model, and encrypted message delivery.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.info(
    "This is a classroom simulation, not real medical or secure messaging. "
    "BB84 here does not use real photons or provide production-grade key distribution."
)

column_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]


@st.cache_resource
def load_classifier():
    return joblib.load("nsl_kdd_model.joblib")


@st.cache_data
def load_test_data():
    return pd.read_csv("KDDTest+.txt", header=None, names=column_names)


classical_ai = load_classifier()
test_df = load_test_data()


def run_bb84(scenario, noise_rate, number_of_qubits=512):
    """Run a fresh BB84-style circuit batch; the randomness changes each run."""
    rng = random.SystemRandom()
    has_eve = scenario in {"Hacker intercept-resend", "Hacker + channel noise"}
    has_noise = scenario in {"Channel noise", "Hacker + channel noise"}

    alice_bits = [rng.randrange(2) for _ in range(number_of_qubits)]
    alice_bases = [rng.choice(("Z", "X")) for _ in range(number_of_qubits)]
    doctor_bases = [rng.choice(("Z", "X")) for _ in range(number_of_qubits)]
    hacker_bases = [rng.choice(("Z", "X")) for _ in range(number_of_qubits)]

    circuits = []
    for i in range(number_of_qubits):
        circuit = QuantumCircuit(1, 2)

        # Hospital encodes a random bit in the Z or X basis.
        if alice_bits[i]:
            circuit.x(0)
        if alice_bases[i] == "X":
            circuit.h(0)

        # The channel may introduce a random X-gate disturbance.
        if has_noise and rng.random() < noise_rate:
            circuit.x(0)

        # The Hacker measures in a random basis and sends a replacement qubit.
        if has_eve:
            if hacker_bases[i] == "X":
                circuit.h(0)
            circuit.measure(0, 0)
            circuit.reset(0)
            with circuit.if_test((circuit.clbits[0], 1)):
                circuit.x(0)
            if hacker_bases[i] == "X":
                circuit.h(0)

        # The Doctor measures in an independently selected basis.
        if doctor_bases[i] == "X":
            circuit.h(0)
        circuit.measure(0, 1)
        circuits.append(circuit)

    result = AerSimulator().run(circuits, shots=1, memory=True).result()
    doctor_bits = []
    hacker_bits = []
    for i in range(number_of_qubits):
        # Aer returns one memory entry per shot; here we requested shots=1.
        memory = result.get_memory(i)[0].replace(" ", "")
        doctor_bits.append(int(memory[-2]))
        hacker_bits.append(int(memory[-1]))

    sifted = [
        i for i in range(number_of_qubits)
        if alice_bases[i] == doctor_bases[i]
    ]
    errors = sum(alice_bits[i] != doctor_bits[i] for i in sifted)
    qber = errors / len(sifted) if sifted else 0.0

    count = min(16, number_of_qubits)
    trace = pd.DataFrame({
        "Qubit": range(1, count + 1),
        "Hospital bit": alice_bits[:count],
        "Hospital basis": alice_bases[:count],
        "Hacker basis": hacker_bases[:count] if has_eve else ["—"] * count,
        "Hacker measurement": hacker_bits[:count] if has_eve else ["—"] * count,
        "Doctor basis": doctor_bases[:count],
        "Doctor measurement": doctor_bits[:count],
        "Kept after sifting": [
            "Yes" if alice_bases[i] == doctor_bases[i] else "No"
            for i in range(count)
        ],
        "Sifted bits agree": [
            "—" if alice_bases[i] != doctor_bases[i]
            else ("Yes" if alice_bits[i] == doctor_bits[i] else "No")
            for i in range(count)
        ],
    })
    return {
        "qber": qber,
        "sifted": len(sifted),
        "errors": errors,
        "trace": trace,
        "alice_bits": alice_bits,
        "sifted_positions": sifted,
    }


def adaptive_limits(noise_rate, has_noise, sifted_count):
    """Demo-only limits adapt to the configured noise and sample size."""
    expected_channel_qber = noise_rate / 2 if has_noise else 0.0
    uncertainty = 1.96 * (0.25 / max(sifted_count, 1)) ** 0.5
    monitor_at = min(0.15, expected_channel_qber + uncertainty + 0.02)
    reject_at = min(0.24, monitor_at + 0.10)
    return monitor_at, reject_at


def final_decision(network_prediction, qber_value, monitor_at, reject_at):
    if network_prediction == 1 or qber_value >= reject_at:
        return "REJECT"
    if qber_value >= monitor_at:
        return "MONITOR"
    return "ACCEPT"


def encrypt_demo_message(message, sifted_bits):
    """AES-GCM encryption using a classroom-model key derived from sifted bits."""
    bit_string = "".join(str(bit) for bit in sifted_bits)
    key = hashlib.sha256(bit_string.encode("ascii")).digest()
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, message.encode("utf-8"), None)
    return key, nonce, ciphertext


st.divider()
st.header("🎛️ Build the demo run")

with st.form("demo_form"):
    left, right = st.columns(2)
    with left:
        st.subheader("1 · Choose a network record")
        record_group = st.selectbox("Traffic type", ["Normal record", "Attack record"])
        records = test_df[test_df["label"] == "normal"] if record_group == "Normal record" else test_df[test_df["label"] != "normal"]
        record_number = st.slider("Example record", 1, min(20, len(records)), 1)
        record_index = records.index[record_number - 1]
        record = test_df.loc[record_index]
        record_features = test_df.drop(columns=["label", "difficulty"]).loc[[record_index]]
        st.write(f"**Dataset label:** `{record['label']}`")
        st.dataframe(
            record_features[["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes"]],
            hide_index=True, width="stretch",
        )

    with right:
        st.subheader("2 · Pick the quantum channel")
        selected_scenario = st.selectbox(
            "What is happening to the qubits?",
            ["Clear channel", "Channel noise", "Hacker intercept-resend", "Hacker + channel noise"],
        )
        noise_percent = st.slider(
            "Channel bit-flip chance", min_value=0, max_value=30, value=10, step=1,
            help="Applied only in the two scenarios that include channel noise. The measured QBER varies randomly each run.",
        )
        message = st.text_area(
            "3 · Judge: type a message for the Doctor",
            placeholder="Example: Please review patient room 204.",
            max_chars=500,
            help="Use a fictional message only; this is a classroom demo.",
        )
    submitted = st.form_submit_button("🚀 Run exchange and send if safe", type="primary", width="stretch")

if submitted:
    noise_rate = noise_percent / 100
    scenario_noise_rate = noise_rate if selected_scenario in {"Channel noise", "Hacker + channel noise"} else 0.0
    scenario_names = ["Clear channel", "Channel noise", "Hacker intercept-resend", "Hacker + channel noise"]
    explanations = {
        "Clear channel": "No added channel noise or Hacker interception.",
        "Channel noise": f"Random X-gate disturbances are applied with a {noise_percent}% chance per qubit.",
        "Hacker intercept-resend": "The Hacker measures each qubit in a random basis and sends a replacement.",
        "Hacker + channel noise": f"The Hacker intercepts and resends while the channel also has {noise_percent}% bit-flip chance.",
    }

    with st.status("📡 The Hospital and Doctor are starting BB84…", expanded=True) as status:
        st.markdown("**1 · Hospital prepares qubits** — random bits are encoded using Z or X bases.")
        time.sleep(0.6)
        st.markdown(f"**2 · Channel** — {explanations[selected_scenario]}")
        time.sleep(0.6)
        has_hacker = selected_scenario in {"Hacker intercept-resend", "Hacker + channel noise"}
        has_noise = selected_scenario in {"Channel noise", "Hacker + channel noise"}
        if has_hacker:
            st.markdown("**3 · Hacker intercepts** — the Hacker measures each qubit, then prepares and sends a replacement.")
        else:
            st.markdown("**3 · Channel playback** — no Hacker is intercepting this run.")
        hacker_actor = (
            '<div class="story-actor hacker-actor"><div class="story-emoji">🕵️</div>'
            '<div class="story-name">Hacker</div><div class="story-sub">intercepts &amp; resends</div></div>'
            if has_hacker else
            '<div class="story-actor"><div class="story-emoji">🌌</div>'
            '<div class="story-name">Quantum channel</div><div class="story-sub">no interceptor</div></div>'
        )
        scene_classes = " ".join([
            "storyboard",
            "has-hacker" if has_hacker else "",
            "has-noise" if has_noise else "",
        ])
        st.markdown(
            f'<div class="{scene_classes}">'
            '<div class="story-title">🎬 BB84 STORY MODE · simulated qubit in transit</div>'
            '<div class="story-line"></div><div class="story-qubit">Q</div>'
            '<div class="story-actors">'
            '<div class="story-actor"><div class="story-emoji">🏥</div>'
            '<div class="story-name">Hospital</div><div class="story-sub">prepares a qubit</div></div>'
            f'{hacker_actor}'
            '<div class="story-actor"><div class="story-emoji">🧑‍⚕️</div>'
            '<div class="story-name">Doctor</div><div class="story-sub">measures the qubit</div></div>'
            '</div><div class="story-caption">glowing orb = one qubit · flashing path = channel noise</div></div>',
            unsafe_allow_html=True,
        )
        selected_result = run_bb84(selected_scenario, scenario_noise_rate)
        st.markdown("**4 · Qubit-by-qubit playback** — watch the simulated transmission appear below.")
        activity = st.empty()
        trace_view = st.empty()
        playback = st.progress(0, text="Preparing the playback…")
        trace = selected_result["trace"]
        for row_number in range(1, len(trace) + 1):
            row = trace.iloc[row_number - 1]
            if has_hacker:
                activity.info(
                    f"📡 Qubit {row['Qubit']}: Hospital sent bit {row['Hospital bit']} in "
                    f"{row['Hospital basis']} basis → Hacker measured {row['Hacker measurement']} "
                    f"in {row['Hacker basis']} basis and resent it → Doctor measured in "
                    f"{row['Doctor basis']} basis. Sifted: {row['Kept after sifting']}."
                )
            else:
                activity.info(
                    f"📡 Qubit {row['Qubit']}: Hospital sent bit {row['Hospital bit']} in "
                    f"{row['Hospital basis']} basis → Doctor measured in {row['Doctor basis']} "
                    f"basis. Sifted: {row['Kept after sifting']}."
                )
            trace_view.dataframe(trace.iloc[:row_number], hide_index=True, width="stretch")
            playback.progress(row_number / len(trace), text=f"Showing qubit {row_number} of {len(trace)}")
            time.sleep(0.25)
        playback.empty()
        time.sleep(0.6)
        st.markdown("**5 · QBER check** — the simulator compares sifted bits to estimate disturbance.")
        st.write(f"Kept **{selected_result['sifted']}** of 512 · Errors **{selected_result['errors']}** · QBER **{selected_result['qber']:.1%}**")

        prediction = int(classical_ai.predict(record_features)[0])
        selected_has_noise = selected_scenario in {"Channel noise", "Hacker + channel noise"}
        monitor_at, reject_at = adaptive_limits(scenario_noise_rate, selected_has_noise, selected_result["sifted"])
        decision = final_decision(prediction, selected_result["qber"], monitor_at, reject_at)
        prediction_name = "ATTACK" if prediction else "NORMAL"
        st.markdown(
            f"**6 · Combined decision** — traffic model: **{prediction_name}** · "
            f"adaptive demo limits: monitor at **{monitor_at:.1%}**, reject at **{reject_at:.1%}** · "
            f"result: **{decision}**"
        )

        if decision == "ACCEPT" and message.strip():
            st.markdown("**7 · Message encryption** — an educational simulated shared key is derived; AES-GCM encrypts the judge’s message.")
            # For this teaching demo, accepted QBER assumes reconciliation and privacy amplification.
            # Those protocol steps are represented here, not implemented as a full QKD stack.
            sifted_bits = [selected_result["alice_bits"][i] for i in selected_result["sifted_positions"]]
            key, nonce, ciphertext = encrypt_demo_message(message, sifted_bits)
            recovered = AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
            st.code(ciphertext.hex(), language="text")
            st.markdown(f"📨 **Doctor decrypts:** {recovered}")
            delivery_text = "Message delivered in the demo."
        elif decision == "ACCEPT":
            delivery_text = "Connection accepted, but no message was entered to send."
        else:
            delivery_text = f"Message blocked: the demo decision is {decision}."
        status.update(label="Exchange walkthrough complete", state="complete", expanded=True)

    st.divider()
    st.header("✨ Run result")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Traffic model", prediction_name)
    m2.metric("Measured QBER", f"{selected_result['qber']:.1%}")
    m3.metric("Adaptive limits", f"{monitor_at:.1%} / {reject_at:.1%}", help="Monitor / reject boundaries for this run.")
    m4.metric("Decision", decision)
    if decision == "ACCEPT":
        st.success(delivery_text)
    elif decision == "MONITOR":
        st.warning(delivery_text)
    else:
        st.error(delivery_text)

    st.subheader("📊 All channel scenarios")
    with st.spinner("Running fresh comparison simulations…"):
        results = {selected_scenario: selected_result}
        for name in scenario_names:
            if name != selected_scenario:
                rate = noise_rate if name in {"Channel noise", "Hacker + channel noise"} else 0.0
                results[name] = run_bb84(name, rate)
    rows = []
    for name in scenario_names:
        has_noise = name in {"Channel noise", "Hacker + channel noise"}
        rate = noise_rate if has_noise else 0.0
        monitor, reject = adaptive_limits(rate, has_noise, results[name]["sifted"])
        rows.append({
            "Scenario": name,
            "QBER": f"{results[name]['qber']:.1%}",
            "Monitor limit": f"{monitor:.1%}",
            "Reject limit": f"{reject:.1%}",
            "Decision": final_decision(prediction, results[name]["qber"], monitor, reject),
        })
    comparison = pd.DataFrame(rows)
    st.dataframe(comparison, hide_index=True, width="stretch")
    chart = pd.DataFrame({"Scenario": scenario_names, "QBER": [results[name]["qber"] for name in scenario_names]})
    st.bar_chart(chart, x="Scenario", y="QBER", width="stretch")

    st.caption(
        "Adaptive limits are illustrative: they account for configured channel noise and sample size, "
        "with a cap. The message step assumes simplified reconciliation/privacy amplification after ACCEPT; "
        "authentication, full error correction, privacy amplification, and real quantum hardware are not implemented."
    )
