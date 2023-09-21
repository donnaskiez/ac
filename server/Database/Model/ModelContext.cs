using Google.Protobuf.Reflection;
using Microsoft.EntityFrameworkCore;
using MySql.EntityFrameworkCore.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace server.Database.Model
{
    public class ModelContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<HardwareConfiguration> HardwareConfiguration { get; set; }
        public DbSet<Report> Reports { get; set; }
        public DbSet<ReportTypeIllegalHandleOperation> ReportTypeIllegalHandleOperation { get; set; }
        public DbSet<ReportTypeStartAddress> ReportTypeStartAddress { get; set; }
        public DbSet<ReportTypePageProtection> ReportTypePageProtection { get; set; }
        public DbSet<ReportTypePatternScan> ReportTypePatternScan { get; set; }
        public DbSet<ReportTypeNmiCallback> ReportTypeNmiCallback { get; set; }
        public DbSet<ReportTypeSystemModuleValidation> ReportTypeSystemModuleValidation { get; set; }

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

            modelBuilder.Entity<Report>(entity =>
            {
                entity.HasKey(e => e.ReportId);

                entity.Property(e => e.ReportId)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportId).Metadata.Name);

                entity.HasOne(d => d.User)
                    .WithMany(e => e.Reports);

                entity.Property(e => e.ReportCode)
                    .IsRequired();
            });

            modelBuilder.Entity<ReportTypeIllegalHandleOperation>(entity =>
            {
                entity.HasKey(e => e.ReportNumber);

                entity.Property(e => e.ReportNumber)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportNumber).Metadata.Name);

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

                entity.HasOne(d => d.Report)
                    .WithMany(f => f.ReportTypeIllegalHandleOperations);
            });

            modelBuilder.Entity<ReportTypeStartAddress>(entity =>
            {
                entity.HasKey(e => e.ReportNumber);

                entity.Property(e => e.ReportNumber)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportNumber).Metadata.Name);

                entity.Property(e => e.ThreadId)
                    .IsRequired();

                entity.Property(e => e.ThreadStartAddress)
                    .IsRequired();

                entity.HasOne(d => d.Report)
                    .WithMany(f => f.ReportTypeStartAddresses);
            });

            modelBuilder.Entity<ReportTypePageProtection>(entity =>
            {
                entity.HasKey(e => e.ReportNumber);

                entity.Property(e => e.ReportNumber)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportNumber).Metadata.Name);

                entity.Property(e => e.AllocationProtection)
                    .IsRequired();

                entity.Property(e => e.AllocationState)
                    .IsRequired();

                entity.Property(e => e.AllocationType)
                    .IsRequired();

                entity.HasOne(d => d.Report)
                    .WithMany(f => f.ReportTypePageProtections);
            });

            modelBuilder.Entity<ReportTypePatternScan>(entity =>
            {
                entity.HasKey(e => e.ReportNumber);

                entity.Property(e => e.ReportNumber)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportNumber).Metadata.Name);

                entity.Property(e => e.SignatureId)
                    .IsRequired();

                entity.Property(e => e.Address)
                    .IsRequired();

                entity.HasOne(d => d.Report)
                    .WithMany(f => f.ReportTypePatternScans);
            });

            modelBuilder.Entity<ReportTypeNmiCallback>(entity =>
            {
                entity.HasKey(e => e.ReportNumber);

                entity.Property(e => e.ReportNumber)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportNumber).Metadata.Name);

                entity.Property(e => e.WereNmisDisabled)
                    .IsRequired();

                entity.Property(e => e.KThreadAddress)
                    .IsRequired();

                entity.Property(e => e.InvalidRip)
                    .IsRequired();

                entity.HasOne(d => d.Report)
                    .WithMany(f => f.ReportTypeNmiCallbacks);
            });

            modelBuilder.Entity<ReportTypeSystemModuleValidation>(entity =>
            {
                entity.HasKey(e => e.ReportNumber);

                entity.Property(e => e.ReportNumber)
                    .UseMySQLAutoIncrementColumn(entity.Property(e => e.ReportNumber).Metadata.Name);

                entity.Property(e => e.ReportType)
                    .IsRequired();

                entity.Property(e => e.DriverBaseAddress)
                    .IsRequired();

                entity.Property(e => e.DriverSize)
                    .IsRequired();

                entity.Property(e => e.ModuleName)
                    .IsRequired();

                entity.HasOne(d => d.Report)
                    .WithMany(f => f.ReportTypeSystemModuleValidations);
            });
        }
    }
}
