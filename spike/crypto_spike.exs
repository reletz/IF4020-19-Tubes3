# Spike: verifikasi perilaku :crypto / :public_key (OTP 29) terhadap spek.
# Pemakaian: elixir spike/crypto_spike.exs <outdir>
[out] = System.argv()
File.mkdir_p!(out)
msg = ~s({"schema":"minisign-manifest/v1","package":"contoh-app"})
File.write!(Path.join(out, "msg.bin"), msg)

fp = fn spki_der -> Base.encode16(:crypto.hash(:sha256, spki_der), case: :lower) end

pem_priv = fn rec -> :public_key.pem_encode([:public_key.pem_entry_encode(:PrivateKeyInfo, rec)]) end
pem_pub = fn rec -> :public_key.pem_encode([:public_key.pem_entry_encode(:SubjectPublicKeyInfo, rec)]) end

save = fn name, priv_rec, pub_rec, sig ->
  File.write!(Path.join(out, "#{name}.key.pem"), pem_priv.(priv_rec))
  File.write!(Path.join(out, "#{name}.pub.pem"), pem_pub.(pub_rec))
  File.write!(Path.join(out, "#{name}.sig"), sig)
  {:SubjectPublicKeyInfo, der, _} = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, pub_rec)
  IO.puts("#{name}: fingerprint=#{fp.(der)} sig_len=#{byte_size(sig)}")
end

# ---- RSA-PSS ----
t = System.monotonic_time(:millisecond)
rsa_priv = :public_key.generate_key({:rsa, 3072, 65537})
IO.puts("rsa keygen ms=#{System.monotonic_time(:millisecond) - t}")
{:RSAPrivateKey, _, n, e, _, _, _, _, _, _, _} = rsa_priv
rsa_pub = {:RSAPublicKey, n, e}
opts = [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 32, rsa_mgf1_md: :sha256]
sig = :public_key.sign(msg, :sha256, rsa_priv, opts)
IO.puts("rsa verify ok=#{:public_key.verify(msg, :sha256, sig, rsa_pub, opts)} bits=#{n |> :binary.encode_unsigned() |> byte_size() |> Kernel.*(8)} e=#{e}")
IO.puts("rsa tamper verify=#{:public_key.verify(msg <> "x", :sha256, sig, rsa_pub, opts)}")
sig2 = :public_key.sign(msg, :sha256, rsa_priv, opts)
IO.puts("rsa two sigs identical=#{sig == sig2}")
save.("rsa", rsa_priv, rsa_pub, sig)

# ---- ECDSA P-256 ----
ec_priv = :public_key.generate_key({:namedCurve, :secp256r1})
{:ECPrivateKey, _, _, params, point, _} = ec_priv
ec_pub = {{:ECPoint, point}, params}
der_sig = :public_key.sign(msg, :sha256, ec_priv)
{:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der_sig)
pad32 = fn i -> b = :binary.encode_unsigned(i); :binary.copy(<<0>>, 32 - byte_size(b)) <> b end
rs = pad32.(r) <> pad32.(s)
<<r2::unsigned-big-256, s2::unsigned-big-256>> = rs
back = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r2, s2})
IO.puts("ecdsa der_len=#{byte_size(der_sig)} rs_len=#{byte_size(rs)} verify(rebuilt DER)=#{:public_key.verify(msg, :sha256, back, ec_pub)}")
bad = :binary.copy(<<0>>, 64)
<<br::unsigned-big-256, bs::unsigned-big-256>> = bad
bad_der = :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", br, bs})
IO.puts("ecdsa r=s=0 verify=#{inspect(try do :public_key.verify(msg, :sha256, bad_der, ec_pub) rescue e -> {:raised, e} end)}")
ec_sig2 = :public_key.sign(msg, :sha256, ec_priv)
IO.puts("ecdsa two sigs identical=#{der_sig == ec_sig2}")
save.("ecdsa", ec_priv, ec_pub, rs)

# ---- Ed25519 ----
ed_res = try do
  ed_priv = :public_key.generate_key({:namedCurve, :ed25519})
  {:ECPrivateKey, _, _, ed_params, ed_point, _} = ed_priv
  ed_pub = {{:ECPoint, ed_point}, ed_params}
  ed_sig = :public_key.sign(msg, :none, ed_priv)
  IO.puts("ed25519 verify=#{:public_key.verify(msg, :none, ed_sig, ed_pub)} params=#{inspect(ed_params)}")
  ed_sig2 = :public_key.sign(msg, :none, ed_priv)
  IO.puts("ed25519 two sigs identical=#{ed_sig == ed_sig2}")
  save.("ed25519", ed_priv, ed_pub, ed_sig)
  :ok
rescue
  e -> IO.puts("ed25519 public_key path FAILED: #{Exception.format(:error, e, __STACKTRACE__)}"); :failed
end
IO.puts("ed25519 result=#{ed_res}")
