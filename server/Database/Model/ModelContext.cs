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
        public DbSet<ReportIllegalHandleOperation> ReportIllegalHandleOperation { get; set; }

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
                    .HasDefaultValue(false);
            });

            modelBuilder.Entity<HardwareConfiguration>(entity =>
            {
                entity.HasKey(e => e.HardwareId);

                entity.Property(e => e.HardwareId)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.HardwareId).Metadata.Name);

                entity.Property(e => e.IsBanned)
                    .HasDefaultValue(false);

                entity.Property(e => e.MotherboardSerial)
                    .IsRequired();

                entity.Property(e => e.DeviceDrive0Serial)
                    .IsRequired();

                entity.HasOne(d => d.User)
                    .WithMany(f => f.HardwareConfigurations);
            });

            modelBuilder.Entity<ReportIllegalHandleOperation>(entity =>
            {
                entity.HasKey(e => e.ReportId);

                entity.Property(e => e.ReportId)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportId).Metadata.Name);

                entity.Property(e => e.IsKernelHandle)
                    .IsRequired();

                entity.Property(e => e.ProcessId)
                    .IsRequired();

                entity.Property(e => e.ThreadId)
                    .IsRequired();

                entity.Property(e => e.DesiredAccess)
                    .IsRequired();

                entity.Property(e => e.ProcessName)
                    .IsRequired();

                entity.HasOne(d => d.User)
                    .WithMany(f => f.ReportIllegalHandleOperations);
            });
        }
    }
}
