using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Principal;

namespace GetADGroupMembersFSP
{
    class Program
    {
        static int Main(string[] args)
        {
            var rootCommand = new RootCommand
            {
                new Option<string>(
                    "--group-name",
                    "The name of the Active Directory group"),
                new Option<bool>(
                    "--recursive",
                    "Whether to retrieve members recursively"),
                new Option<string>(
                    "--output-csv-file",
                    "The path to the output CSV file"),
                new Option<string>(
                    "--csv-delimiter",
                    () => ",",
                    "The delimiter to use in the CSV file"),
                new Option<string>(
                    "--username",
                    "The username to connect to Active Directory"),
                new Option<string>(
                    "--password",
                    "The password to connect to Active Directory"),
                new Option<string>(
                    "--domain",
                    "The domain to connect to Active Directory")
            };

            rootCommand.Description = "GetADGroupMembersFSP - A tool to retrieve members of an Active Directory group and export them to a CSV file.";

            rootCommand.Handler = CommandHandler.Create<string, bool, string, string, string, string, string>((groupName, recursive, outputCsvFile, csvDelimiter, username, password, domain) =>
            {
                if (string.IsNullOrEmpty(groupName))
                {
                    Console.WriteLine("GroupName is required.");
                    return;
                }

                PrincipalContext ctx;
                if (string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
                {
                    Console.WriteLine("Using current authenticated user context.");
                    WindowsIdentity identity = WindowsIdentity.GetCurrent();
                    string userDomain = identity.Name.Split('\\')[0];
                    ctx = new PrincipalContext(ContextType.Domain, userDomain);
                    Console.WriteLine($"Using PrincipalContext with current user: {identity.Name}");
                }
                else
                {
                    if (string.IsNullOrEmpty(username))
                    {
                        username = Environment.UserName;
                        if (string.IsNullOrEmpty(username))
                        {
                            Console.Write("Enter username: ");
                            username = Console.ReadLine();
                        }
                    }

                    if (string.IsNullOrEmpty(domain))
                    {
                        domain = Environment.UserDomainName;
                        if (string.IsNullOrEmpty(domain))
                        {
                            Console.Write("Enter domain: ");
                            domain = Console.ReadLine();
                        }
                    }

                    if (string.IsNullOrEmpty(password))
                    {
                        Console.Write("Enter password: ");
                        password = ReadPassword();
                    }

                    ctx = new PrincipalContext(ContextType.Domain, domain, username, password);
                    Console.WriteLine($"Using PrincipalContext with domain: {domain}, username: {username}");
                }

                // Call the method to get group members
                var members = GetGroupMembers(groupName, recursive, ctx);

                // Export to CSV if specified
                if (!string.IsNullOrEmpty(outputCsvFile))
                {
                    ExportToCsv(members, outputCsvFile, csvDelimiter);
                }

                // Display the results
                Console.WriteLine($"Domain Name: {GetDomainName()}");
                Console.WriteLine($"Group Name: {groupName}");
                Console.WriteLine($"Total Members: {members.Count}");

                var uniqueMembers = members
                    .GroupBy(m => m.DistinguishedName)
                    .Select(g => new
                    {
                        Member = g.First(),
                        Count = g.Count()
                    })
                    .ToList();

                Console.WriteLine($"Unique Members: {uniqueMembers.Count}");

                foreach (var member in uniqueMembers)
                {
                    if (member.Count > 1)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                    }
                    Console.WriteLine($"{member.Member.DistinguishedName}, {member.Member.ObjectClass}, {member.Member.NTAccount} (Memberships: {member.Count})");
                }

                // Reset the console color
                Console.ResetColor();
            });

            return rootCommand.InvokeAsync(args).Result;
        }

        static List<GroupMember> GetGroupMembers(string groupName, bool recursive, PrincipalContext ctx)
        {
            List<GroupMember> members = new List<GroupMember>();
            try
            {
                using (ctx)
                {
                    GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, groupName);
                    if (group != null)
                    {
                        if (recursive)
                        {
                            GetGroupMembersRecursive(group, members);
                        }
                        else
                        {
                            foreach (Principal p in group.GetMembers())
                            {
                                members.Add(new GroupMember
                                {
                                    DistinguishedName = p.DistinguishedName,
                                    ObjectClass = p.StructuralObjectClass,
                                    NTAccount = ResolveNTAccount(p)
                                });
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Group '{groupName}' not found.");
                    }
                }
            }
            catch (PrincipalOperationException ex)
            {
                Console.WriteLine($"Authentication error: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            return members;
        }

        static void GetGroupMembersRecursive(GroupPrincipal group, List<GroupMember> members)
        {
            foreach (Principal p in group.GetMembers())
            {
                members.Add(new GroupMember
                {
                    DistinguishedName = p.DistinguishedName,
                    ObjectClass = p.StructuralObjectClass,
                    NTAccount = ResolveNTAccount(p)
                });
                if (p is GroupPrincipal nestedGroup)
                {
                    GetGroupMembersRecursive(nestedGroup, members);
                }
            }
        }

        static string ResolveNTAccount(Principal principal)
        {
            if (principal is UserPrincipal user)
            {
                return $"{GetNetBIOSDomainName(user.Context)}\\{user.SamAccountName}";
            }
            else if (principal is GroupPrincipal group)
            {
                return $"{GetNetBIOSDomainName(group.Context)}\\{group.SamAccountName}";
            }
            else if (principal is AuthenticablePrincipal authPrincipal)
            {
                SecurityIdentifier sid = authPrincipal.Sid;
                try
                {
                    NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                    return ntAccount.Value;
                }
                catch (Exception)
                {
                    return "Unresolved NTAccount";
                }
            }
            return "Unknown NTAccount";
        }

        static string GetNetBIOSDomainName(PrincipalContext context)
        {
            using (var searcher = new DirectorySearcher(new DirectoryEntry("LDAP://" + context.ConnectedServer)))
            {
                searcher.Filter = "(objectClass=domain)";
                searcher.PropertiesToLoad.Add("name");
                var result = searcher.FindOne();
                if (result != null)
                {
                    return result.Properties["name"][0].ToString();
                }
            }
            return "UnknownDomain";
        }

        static void ExportToCsv(List<GroupMember> members, string filePath, string delimiter)
        {
            var uniqueMembers = members
                .GroupBy(m => m.DistinguishedName)
                .Select(g => new
                {
                    Member = g.First(),
                    Count = g.Count()
                })
                .ToList();

            using (var writer = new StreamWriter(filePath))
            {
                writer.WriteLine($"DistinguishedName{delimiter}ObjectClass{delimiter}NTAccountName{delimiter}MembershipCount");
                foreach (var member in uniqueMembers)
                {
                    writer.WriteLine($"{member.Member.DistinguishedName}{delimiter}{member.Member.ObjectClass}{delimiter}{member.Member.NTAccount}{delimiter}{member.Count}");
                }
            }
        }

        static string GetDomainName()
        {
            try
            {
                return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving domain name: {ex.Message}");
                return "Unknown Domain";
            }
        }

        static string ReadPassword()
        {
            string password = string.Empty;
            ConsoleKeyInfo info;
            do
            {
                info = Console.ReadKey(true);
                if (info.Key != ConsoleKey.Backspace && info.Key != ConsoleKey.Enter)
                {
                    password += info.KeyChar;
                    Console.Write("*");
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password.Substring(0, password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
            } while (info.Key != ConsoleKey.Enter);
            Console.WriteLine();
            return password;
        }
    }

    class GroupMember
    {
        public string DistinguishedName { get; set; }
        public string ObjectClass { get; set; }
        public string NTAccount { get; set; }
    }
}