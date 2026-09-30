import time
import streamlit as st

st.set_page_config(
    page_title="2차원 헤논 맵 카오스 암호화", page_icon="🌀"
)

st.title("🌀 2차원 헤논 맵(Hénon Map) 카오스 암호화 시뮬레이터")
st.caption("디피-헬만 키 교환과 2차원 카오스 계를 결합한 보안 강화 모델")

# 1. 키 생성 섹션
st.header("1. 디피-헬만 기반 헤논 비밀키 생성")
col1, col2 = st.columns(2)
with col1:
    q = st.number_input("소수 q", value=1000000007)
    a_priv = st.number_input("A 비밀키 a", value=123456)
with col2:
    p = st.number_input("원시근 p", value=5)
    b_priv = st.number_input("B 비밀키 b", value=654321)


def get_henon_val(x1, y1, a_param, b_param, N):
    x, y = x1, y1
    for _ in range(N - 1):
        next_x = 1.0 - a_param * (x**2) + y
        next_y = b_param * x
        x, y = next_x, next_y
    return x, y


# 키 계산
shared_secret = pow(pow(p, b_priv, q), a_priv, q)
norm_val = shared_secret / q
x1 = -0.5 + norm_val * 1.0
y1 = -0.2 + norm_val * 0.4
a_param = 1.35 + norm_val * 0.09
b_param = 0.28 + norm_val * 0.04

st.info(
    f"🔑 **생성된 파라미터:** x1={x1:.6f}, y1={y1:.6f}, a={a_param:.6f}, b={b_param:.6f}"
)

# 2. 암호화 섹션
st.header("2. 암호화 & 복호화 테스트")
msg = st.text_input("평문 메시지 입력", value="hellomotherfucker")

if st.button("🔒 암호화 실행"):
    t0 = time.time()
    hex_tokens = []
    for idx, char in enumerate(msg):
        ascii_val = ord(char)
        N = 50 + (idx * 17) % 100
        x_n, y_n = get_henon_val(x1, y1, a_param, b_param, N)
        combined_val = int(abs(x_n * 1e6) + abs(y_n * 1e6))
        mask_key = combined_val % 256
        encrypted_byte = ascii_val ^ mask_key
        hex_tokens.append(f"{encrypted_byte:02x}")

    t1 = time.time()
    cipher_text = "".join(hex_tokens)
    st.session_state["cipher_text"] = cipher_text
    st.success(f"**암호문 (16진수):** `{cipher_text}` ({t1-t0:.4f}초 소요)")

# 3. 복호화 섹션
cipher_input = st.text_input(
    "복호화할 암호문", value=st.session_state.get("cipher_text", "")
)

if st.button("🔓 복호화 실행"):
    if cipher_input:
        t0 = time.time()
        tokens = [
            cipher_input[i : i + 2] for i in range(0, len(cipher_input), 2)
        ]
        decrypted_chars = []
        for idx, hex_str in enumerate(tokens):
            enc_byte = int(hex_str, 16)
            N = 50 + (idx * 17) % 100
            x_n, y_n = get_henon_val(x1, y1, a_param, b_param, N)
            combined_val = int(abs(x_n * 1e6) + abs(y_n * 1e6))
            mask_key = combined_val % 256
            orig_ascii = enc_byte ^ mask_key
            decrypted_chars.append(chr(orig_ascii))

        t1 = time.time()
        st.success(
            f"**복호화 결과:** `{''.join(decrypted_chars)}` ({t1-t0:.4f}초 소요)"
        )
