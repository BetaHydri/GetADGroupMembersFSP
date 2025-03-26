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
            RootCommand rootCommand = new RootCommand
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
                // Added parameters for username, password, and domain to allow explicit credential usage
                new Option<string>(
                    "--username",
                    "The username to use for Active Directory authentication"),
                new Option<string>(
                    "--password",
                    "The password to use for Active Directory authentication"),
                new Option<string>(
                    "--domain",
                    "The domain to use for Active Directory authentication"),
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

                try
                {
                    // Attempt to retrieve the current domain name
                    string currentDomain = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
                    Console.WriteLine($"Retrieved domain name: {currentDomain}");

                    if (string.IsNullOrEmpty(currentDomain))
                    {
                        throw new Exception("Unable to determine the current domain name.");
                    }

                    // Use provided username and password if available
                    if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                    {
                        ctx = new PrincipalContext(ContextType.Domain, currentDomain, username, password);
                        Console.WriteLine("PrincipalContext created successfully using provided credentials.");

                        // Validate the provided credentials
                        if (!ctx.ValidateCredentials(username, password, ContextOptions.Negotiate))
                        {
                            throw new Exception("Validation of provided credentials failed.");
                        }
                        Console.WriteLine("Validation of provided credentials succeeded.");
                    }
                    else if (string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
                    {
                        // Use current Windows identity if no credentials are provided
                        ctx = new PrincipalContext(ContextType.Domain, currentDomain, null, ContextOptions.Negotiate);
                        Console.WriteLine("PrincipalContext created successfully using current Windows identity.");
                    }
                    else
                    {
                        throw new Exception("The user name and password must either both be null or both must be non-null.");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: Unable to connect to Active Directory. {ex.Message}");
                    Console.WriteLine("Please ensure the machine is joined to the domain and the current user has sufficient permissions.");
                    return;
                }

                // Call the method to get group members
                List<GroupMember> members = GetGroupMembers(groupName, recursive, ctx);

                // Export to CSV if specified
                if (!string.IsNullOrEmpty(outputCsvFile))
                {
                    try
                    {
                        ExportToCsv(members, outputCsvFile, csvDelimiter);
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        Console.WriteLine($"Unauthorized access error: {ex.Message}");
                        return;
                    }
                }

                // Display the results
                Console.WriteLine($"Domain Name: {GetDomainName()}");
                Console.WriteLine($"Group Name: {groupName}");

                int totalMembers = members.Sum(m => m.DirectGroups.Count);
                var uniqueMembers = members
                    .GroupBy(m => m.DistinguishedName)
                    .Select(g => new
                    {
                        Member = g.First(),
                        Count = g.First().DirectGroups.Count
                    })
                    .ToList();

                Console.WriteLine($"Total Members: {totalMembers}");
                Console.WriteLine($"Unique Members: {uniqueMembers.Count}");

                int maxDistinguishedNameLength = uniqueMembers.Any() ? uniqueMembers.Max(m => m.Member.DistinguishedName.Length) : 0;
                int maxObjectClassLength = uniqueMembers.Any() ? uniqueMembers.Max(m => m.Member.ObjectClass.Length) : 0;
                int maxNTAccountNameLength = uniqueMembers.Any() ? uniqueMembers.Max(m => m.Member.NTAccount.Length) : 0;
                int maxDirectGroupsLength = uniqueMembers.Any() ? uniqueMembers.Max(m => string.Join(", ", m.Member.DirectGroups).Length) : 0;

                Console.WriteLine($"| {"DistinguishedName".PadRight(maxDistinguishedNameLength)} | {"Class".PadRight(maxObjectClassLength)} | {"NTAccountName".PadRight(maxNTAccountNameLength)} | MembershipCount| {"DirectGroups".PadRight(maxDirectGroupsLength)} |");
                Console.WriteLine($"|{new string('-', maxDistinguishedNameLength + 2)}|{new string('-', maxObjectClassLength + 2)}|{new string('-', maxNTAccountNameLength + 2)}|----------------|{new string('-', maxDirectGroupsLength + 2)}|");
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
                    Console.WriteLine($"| {member.Member.DistinguishedName.PadRight(maxDistinguishedNameLength)} | {member.Member.ObjectClass.PadRight(maxObjectClassLength)} | {member.Member.NTAccount.PadRight(maxNTAccountNameLength)} | {member.Count.ToString().PadRight(14)} | {string.Join(", ", member.Member.DirectGroups).PadRight(maxDirectGroupsLength)} |");
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
                    Console.WriteLine($"Attempting to find group: {groupName}");
                    GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, groupName);
                    if (group != null)
                    {
                        Console.WriteLine($"Group '{groupName}' found.");
                        if (recursive)
                        {
                            Console.WriteLine("Retrieving members recursively.");
                            GetGroupMembersRecursive(group, members);
                        }
                        else
                        {
                            Console.WriteLine("Retrieving direct members.");
                            foreach (Principal p in group.GetMembers())
                            {
                                Console.WriteLine($"Found member: {p.DistinguishedName}");
                                if (p is AuthenticablePrincipal authPrincipal && authPrincipal.StructuralObjectClass == "foreignsecurityprincipal")
                                {
                                    Console.WriteLine($"ForeignSecurityPrincipal detected: {p.DistinguishedName}");
                                    string domain = ParseDomainFromDistinguishedName(p.DistinguishedName);
                                    Console.WriteLine($"Domain: {domain}");

                                    Console.Write("Enter username for foreign domain: ");
                                    string username = Console.ReadLine();

                                    Console.Write("Enter password for foreign domain: ");
                                    string password = ReadPassword();

                                    try
                                    {
                                        using (PrincipalContext foreignCtx = new PrincipalContext(ContextType.Domain, domain, username, password))
                                        {
                                            if (foreignCtx.ValidateCredentials(username, password))
                                            {
                                                members.Add(CreateGroupMember(p, group.Name));
                                            }
                                            else
                                            {
                                                Console.WriteLine("Invalid credentials for the foreign domain.");
                                            }
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine($"Error connecting to foreign domain: {ex.Message}");
                                    }
                                }
                                else
                                {
                                    members.Add(CreateGroupMember(p, group.Name));
                                }
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

        static void GetGroupMembersRecursive(GroupPrincipal group, List<GroupMember> members, List<string> parentGroups = null)
        {
            if (parentGroups == null)
            {
                parentGroups = new List<string>();
            }
            parentGroups.Add(group.Name);

            foreach (Principal p in group.GetMembers())
            {
                try
                {
                    GroupMember member = members.FirstOrDefault(m => m.DistinguishedName == p.DistinguishedName);
                    if (member == null)
                    {
                        member = CreateGroupMember(p, group.Name);
                        members.Add(member);
                    }
                    else
                    {
                        member.DirectGroups.Add(group.Name);
                    }

                    if (p is GroupPrincipal nestedGroup)
                    {
                        Console.WriteLine($"Recursively retrieving members of nested group: {nestedGroup.Name}");
                        GetGroupMembersRecursive(nestedGroup, members, parentGroups);
                    }
                }
                catch (PrincipalOperationException ex)
                {
                    Console.WriteLine($"Error retrieving member: {p.Name}. {ex.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Unexpected error retrieving member: {p.Name}. {ex.Message}");
                }
            }
            parentGroups.Remove(group.Name);
        }

        static GroupMember CreateGroupMember(Principal principal, string groupName)
        {
            GroupMember member = new GroupMember
            {
                DistinguishedName = principal.DistinguishedName,
                ObjectClass = principal.StructuralObjectClass,
                NTAccount = principal.StructuralObjectClass == "foreignsecurityprincipal" ? ResolveForeignSecurityPrincipalNTAccount(principal) : ResolveNTAccount(principal),
                DirectGroups = new List<string> { groupName }
            };
            return member;
        }

        static string ResolveForeignSecurityPrincipalNTAccount(Principal principal)
        {
            if (principal is AuthenticablePrincipal authPrincipal)
            {
                SecurityIdentifier sid = authPrincipal.Sid;
                try
                {
                    NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                    return ntAccount.Value;
                }
                catch (IdentityNotMappedException)
                {
                    Console.WriteLine("ForeignSecurityPrincipal detected. Please provide credentials for the trusted domain.");

                    // Parse the domain from the DistinguishedName
                    string domain = ParseDomainFromDistinguishedName(principal.DistinguishedName);
                    Console.WriteLine($"Domain: {domain}");

                    Console.Write("Enter username: ");
                    string username = Console.ReadLine();

                    Console.Write("Enter password: ");
                    string password = ReadPassword();

                    // Attempt to resolve the NTAccount using the provided credentials
                    try
                    {
                        using (PrincipalContext ctx = new PrincipalContext(ContextType.Domain, domain, username, password))
                        {
                            if (ctx.ValidateCredentials(username, password))
                            {
                                NTAccount ntAccount = (NTAccount)sid.Translate(typeof(NTAccount));
                                return ntAccount.Value;
                            }
                            else
                            {
                                Console.WriteLine("Invalid credentials for the trusted domain.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error resolving ForeignSecurityPrincipal: {ex.Message}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error resolving ForeignSecurityPrincipal: {ex.Message}");
                }
            }
            return "Unknown NTAccount";
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
            using (DirectorySearcher searcher = new DirectorySearcher(new DirectoryEntry("LDAP://" + context.ConnectedServer)))
            {
                searcher.Filter = "(objectClass=domain)";
                searcher.PropertiesToLoad.Add("name");
                SearchResult result = searcher.FindOne();
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
                    Count = g.First().DirectGroups.Count
                })
                .ToList();

            using (StreamWriter writer = new StreamWriter(filePath))
            {
                writer.WriteLine($"DistinguishedName{delimiter}ObjectClass{delimiter}NTAccountName{delimiter}MembershipCount{delimiter}DirectGroups");
                foreach (var member in uniqueMembers)
                {
                    writer.WriteLine($"{member.Member.DistinguishedName}{delimiter}{member.Member.ObjectClass}{delimiter}{member.Member.NTAccount}{delimiter}{member.Count}{delimiter}{string.Join("|", member.Member.DirectGroups)}");
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

        static string ParseDomainFromDistinguishedName(string distinguishedName)
        {
            // Extract the domain components (DC=...) from the DistinguishedName
            string[] domainComponents = distinguishedName.Split(',')
                .Where(part => part.TrimStart().StartsWith("DC="))
                .Select(part => part.Substring(3))
                .ToArray();

            // Join the domain components to form the domain name
            return string.Join(".", domainComponents);
        }

        static void HandleForeignSecurityPrincipal(Principal principal, List<GroupMember> members, string parentGroupName)
        {
            if (principal is AuthenticablePrincipal authPrincipal && authPrincipal.StructuralObjectClass == "foreignsecurityprincipal")
            {
                Console.WriteLine($"ForeignSecurityPrincipal detected: {principal.DistinguishedName}");

                // Parse the domain from the DistinguishedName
                string domain = ParseDomainFromDistinguishedName(principal.DistinguishedName);
                Console.WriteLine($"Domain: {domain}");

                // Prompt for credentials
                Console.Write("Enter username for foreign domain: ");
                string username = Console.ReadLine();

                Console.Write("Enter password for foreign domain: ");
                string password = ReadPassword();

                try
                {
                    using (PrincipalContext foreignCtx = new PrincipalContext(ContextType.Domain, domain, username, password))
                    {
                        if (foreignCtx.ValidateCredentials(username, password))
                        {
                            Console.WriteLine("Credentials validated successfully for foreign domain.");
                            members.Add(CreateGroupMember(principal, parentGroupName));
                        }
                        else
                        {
                            Console.WriteLine("Invalid credentials for the foreign domain.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error connecting to foreign domain: {ex.Message}");
                }
            }
        }
    }

    class GroupMember
    {
        public string DistinguishedName { get; set; }
        public string ObjectClass { get; set; }
        public string NTAccount { get; set; }
        public List<string> DirectGroups { get; set; } = new List<string>();
    }
}