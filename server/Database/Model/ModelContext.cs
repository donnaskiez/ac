using Microsoft.EntityFrameworkCore;
using MySql.EntityFrameworkCore.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server.Database.Model
{
    public class ModelContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<HardwareConfiguration> HardwareConfiguration { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseMySQL("server=localhost;userid=root;password=root;database=ac_db");
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserId);

                entity.Property(e => e.UserId)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.UserId).Metadata.Name);

                entity.Property(e => e.Steam64Id)
                    .IsRequired();

                entity.Property(e => e.IsBanned)
                    .IsRequired();

                entity.HasMany(g => g.HardwareConfigurations)
                    .WithOne(s => s.User)
                    .HasForeignKey(s => s.UserId)
                    .HasPrincipalKey(keyExpression: e => e.UserId);
            });

            modelBuilder.Entity<HardwareConfiguration>(entity =>
            {
                entity.HasKey(e => e.HardwareId);

                entity.Property(e => e.HardwareId)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.HardwareId).Metadata.Name);

                entity.Property(f => f.IsBanned)
                    .HasDefaultValue(false);

                entity.HasOne(s => s.User)
                    .WithMany(g => g.HardwareConfigurations)
                    .HasForeignKey(s => s.UserId);
            });
        }
    }
}
