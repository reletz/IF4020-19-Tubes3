defmodule Nadina.Artifact do
  @moduledoc """
  Pembacaan artefak: ukuran dan SHA-256 dari byte berkas.

  Berkas dibaca sebagai byte apa adanya, per potongan, tanpa normalisasi dan tanpa
  menjalankan atau mengekstrak isinya.
  """

  @chunk 1024 * 1024

  @doc """
  Menghitung ukuran dan SHA-256 (hex huruf kecil) dari berkas.

  ## Contoh

      iex> path = Path.join(System.tmp_dir!(), "nadina-artifact-doctest")
      iex> File.write!(path, "")
      iex> Nadina.Artifact.digest(path)
      {:ok, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
  """
  @spec digest(Path.t()) :: {:ok, non_neg_integer(), String.t()} | {:error, {:io, File.posix()}}
  def digest(path) do
    case File.open(path, [:read, :binary, :raw]) do
      {:ok, io} ->
        try do
          read_all(io, :crypto.hash_init(:sha256), 0)
        after
          File.close(io)
        end

      {:error, posix} ->
        {:error, {:io, posix}}
    end
  end

  defp read_all(io, ctx, size) do
    case :file.read(io, @chunk) do
      {:ok, data} ->
        read_all(io, :crypto.hash_update(ctx, data), size + byte_size(data))

      :eof ->
        {:ok, size, ctx |> :crypto.hash_final() |> Base.encode16(case: :lower)}

      {:error, posix} ->
        {:error, {:io, posix}}
    end
  end
end
