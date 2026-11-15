defmodule Nadina.Bundle do
  @moduledoc """
  Bundle tanda tangan (spek Tabel 2.4): byte manifest M dan tanda tangan, keduanya Base64.

  `parse/1` hanya memeriksa format bundle. Isi manifest diperiksa `Nadina.Manifest.parse/1`,
  panjang tanda tangan diperiksa saat verifikasi tanda tangan.
  """

  @schema_id "minisign-bundle/v1"
  @max_size 64 * 1024

  @json_schema {:object,
                [{"schema", :string}, {"manifest_b64", :string}, {"signature_b64", :string}]}

  @enforce_keys [:manifest, :signature]
  defstruct @enforce_keys

  @type t :: %__MODULE__{manifest: binary(), signature: binary()}

  @type parse_error ::
          {:too_large, pos_integer()}
          | Nadina.StrictJSON.decode_error()
          | Nadina.StrictJSON.validate_error()
          | {:invalid_field, [String.t()]}
          | {:invalid_base64, [String.t()]}

  @doc "Ukuran maksimum bundle dalam byte (64 KiB)."
  @spec max_size() :: pos_integer()
  def max_size, do: @max_size

  @doc """
  Encode bundle ke JSON.

      iex> Nadina.Bundle.encode(%Nadina.Bundle{manifest: "a", signature: "bc"})
      ~s({"schema":"minisign-bundle/v1","manifest_b64":"YQ==","signature_b64":"YmM="}\\n)
  """
  @spec encode(t()) :: binary()
  def encode(%__MODULE__{manifest: manifest, signature: signature}) do
    ~s({"schema":"#{@schema_id}","manifest_b64":"#{Base.encode64(manifest)}",) <>
      ~s("signature_b64":"#{Base.encode64(signature)}"}\n)
  end

  @doc "Parse strict bundle. Ukuran dicek sebelum parsing."
  @spec parse(binary()) :: {:ok, t()} | {:error, parse_error()}
  def parse(bytes) when byte_size(bytes) > @max_size, do: {:error, {:too_large, byte_size(bytes)}}

  def parse(bytes) when is_binary(bytes) do
    with {:ok, doc} <- Nadina.StrictJSON.decode_as(bytes, @json_schema),
         :ok <- check_schema_id(doc["schema"]),
         {:ok, manifest} <- decode64(doc["manifest_b64"], "manifest_b64"),
         {:ok, signature} <- decode64(doc["signature_b64"], "signature_b64") do
      {:ok, %__MODULE__{manifest: manifest, signature: signature}}
    end
  end

  defp check_schema_id(@schema_id), do: :ok
  defp check_schema_id(_), do: {:error, {:invalid_field, ["schema"]}}

  # decode lalu encode ulang supaya padding bit dan bentuk non-canonical ikut tertolak
  defp decode64(string, field) do
    with {:ok, bytes} <- Base.decode64(string),
         ^string <- Base.encode64(bytes) do
      {:ok, bytes}
    else
      _ -> {:error, {:invalid_base64, [field]}}
    end
  end
end
