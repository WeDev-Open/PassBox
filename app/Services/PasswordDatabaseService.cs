using System.Security;
using System.Security.Cryptography;
using System.Text;
using LiteDB;
using PassboxApp.Models;

namespace PassboxApp.Services
{
    public class PasswordDatabaseService : IDisposable
    {
        private LiteDatabase _db;
        private ILiteCollection<PasswordEntry> _collection;
        //private readonly Aes _aes;
        private readonly ISecurityService security;
        private readonly string secAlias = "dbrecordkey";
        //public PasswordDatabaseService()
        //{
        //    _aes = Aes.Create();
        //    _aes.KeySize = 32;
        //    _aes.BlockSize = 128;
        //    _aes.Mode = CipherMode.CBC;
         
        //}

        public PasswordDatabaseService(ISecurityService security)
        {
            this.security = security;
        }

        //public void Init(string dbName, SecureString dbPwd)
        //{
        //    _db = new LiteDatabase($"Filename={dbName}; Password={dbPwd}");
        //    _collection = _db.GetCollection<PasswordEntry>("passwords");
            
        //    // Load or generate encryption key
        //    var settings = _db.GetCollection<AppSettings>("settings");
        //    var keySetting = settings.FindOne(x => x.Key == "EncryptionKey");

        //    if (keySetting == null)
        //    {
        //        _aes.GenerateKey();
        //        settings.Insert(new AppSettings
        //        {
        //            Key = "EncryptionKey",
        //            Value = Convert.ToBase64String(_aes.Key)
        //        });
        //    }
        //    else
        //    {
        //        _aes.Key = Convert.FromBase64String(keySetting.Value);
        //    }
        //}

        public void Init(string dbName, SecureString dbPwd)
        {
            _db = new LiteDatabase($"Filename={dbName}; Password={dbPwd}");
            _collection = _db.GetCollection<PasswordEntry>("passwords");

        }

        public void Update(PasswordEntry entry)
        {
            entry.EncryptedPassword = Encrypt($"{secAlias}{entry.Alias}",entry.EncryptedPassword);
            entry.Password = null; // Clear plaintext
            _collection.Update(entry);
        }

        public void Delete(Guid id)
        {
            _collection.Delete(id);
        }

        public void Add(PasswordEntry entry)
        {
            //Encrypt password before storing
            entry.EncryptedPassword = Encrypt($"{secAlias}{entry.Alias}", entry.EncryptedPassword);
            entry.Password = null; // Clear plaintext
            var result= _collection.Insert(entry);
            
        }

        public int GetCount()
        {
            return _collection.Count();
        }
        public List<PasswordEntry> Search(string search = null,int pageSize=10,int pageIndex=1)
        {
            var query = _collection.Query().OrderByDescending(c=>c.CreatedAt);

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(x =>
                    x.Title.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                    x.Username.Contains(search, StringComparison.OrdinalIgnoreCase));
            }

            var results = query.Skip((pageIndex-1)*pageSize).Limit(pageSize).ToList();

            // Decrypt passwords
            foreach (var entry in results)
            {
                entry.Password = null;
                entry.EncryptedPassword = Decrypt($"{secAlias}{entry.Alias}", entry.EncryptedPassword); // Clear encrypted data
            }

            return results;
        }

        private string Encrypt(string alias,string plainText)
        {
            return security.Encrypt(alias, plainText);
            //using var encryptor = _aes.CreateEncryptor();
            //var plainBytes = Encoding.UTF8.GetBytes(plainText);
            //var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            //return Convert.ToBase64String(encryptedBytes);
        }

        private string Decrypt(string alias, string encryptedText)
        {
            return security.Decrypt(alias, encryptedText);
            //using var decryptor = _aes.CreateDecryptor();
            //var encryptedBytes = Convert.FromBase64String(encryptedText);
            //var plainBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            //return Encoding.UTF8.GetString(plainBytes);
        }

        public void Dispose()
        {
            //_aes.Dispose();
            _db.Dispose();
        }
    }

    

   
}
