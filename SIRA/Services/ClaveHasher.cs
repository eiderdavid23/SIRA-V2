using System.Security.Cryptography;

namespace SIRA.Services
{
    public interface IClaveHasher
    {
        string Hashear(string clave);
        bool Verificar(string claveGuardada, string claveIngresada);
        bool EstaHasheada(string claveGuardada);
    }

    public class ClaveHasher : IClaveHasher
    {
        private const string Prefijo = "PBKDF2";
        private const int Iteraciones = 210_000;
        private const int TamSal = 16;
        private const int TamHash = 64;

        public string Hashear(string clave)
        {
            var sal  = RandomNumberGenerator.GetBytes(TamSal);
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                clave, sal, Iteraciones, HashAlgorithmName.SHA512, TamHash);
            return $"{Prefijo}${Iteraciones}${Convert.ToBase64String(sal)}${Convert.ToBase64String(hash)}";
        }

        public bool EstaHasheada(string claveGuardada) =>
            claveGuardada.StartsWith(Prefijo + "$", StringComparison.Ordinal);

        public bool Verificar(string claveGuardada, string claveIngresada)
        {
            if (!EstaHasheada(claveGuardada)) return false;

            var partes = claveGuardada.Split('$');
            if (partes.Length != 4 || !int.TryParse(partes[1], out var iter)) return false;

            try
            {
                var sal      = Convert.FromBase64String(partes[2]);
                var esperado = Convert.FromBase64String(partes[3]);
                var calculado = Rfc2898DeriveBytes.Pbkdf2(
                    claveIngresada, sal, iter, HashAlgorithmName.SHA512, esperado.Length);
                return CryptographicOperations.FixedTimeEquals(calculado, esperado);
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}
