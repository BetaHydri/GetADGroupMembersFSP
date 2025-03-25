# GetADGroupMembersFSP

## Overview
GetADGroupMembersFSP is a .NET console application that retrieves members of an Active Directory group. It allows for recursive retrieval of nested group members and can export the results to a CSV file. The application can prompt for credentials if not provided and handle authentication errors.

## Features
- Parse command-line arguments for group name, recursive retrieval, output CSV file, CSV delimiter, username, password, and domain.
- Retrieve members of a specified Active Directory group.
- Optionally retrieve members recursively from nested groups.
- Export the results to a specified CSV file.
- Display additional information such as the domain name, group name, total members, unique members, and direct group memberships.
- Prompt for credentials if not provided and handle authentication errors.

## Prerequisites
- .NET SDK installed on your machine.
- Access to an Active Directory environment.

## Building the Project
1. Open a terminal and navigate to the project directory.
2. Run the following command to build the project:
   ```sh
   dotnet build
   ```

## Publishing the Project
1. Open a terminal and navigate to the project directory.
2. Run the following command to publish the project as a single executable:
   ```sh
   dotnet publish -c Release -r win-x64 --self-contained
   ```
3. Move the executable file from the `bin\Release\net6.0\win-x64\publish` directory to the main directory of the project.

## Running the Application
To run the application, use the following command format:
```sh
GetADGroupMembersFSP.exe --group-name "YourGroupName" [--recursive] [--output-csv-file "path/to/output.csv"] [--csv-delimiter ","] [--username "username"] [--password "password"] [--domain "domainname"]
```

### Command-Line Arguments
- `--group-name` (required): The name of the Active Directory group to retrieve members from.
- `--recursive`: Optional flag to retrieve members recursively from nested groups.
- `--output-csv-file`: Optional path to save the output as a CSV file.
- `--csv-delimiter`: Optional delimiter for the CSV file (default is a comma).
- `--username`: Optional username to connect to Active Directory in the form `username`.
- `--password`: Optional password to connect to Active Directory.
- `--domain`: Optional domain to connect to Active Directory.

If the `--username` and `--password` parameters are not provided, the application will prompt for credentials. If the authentication fails, the user will be prompted to enter the password again.

## Example
To retrieve members of the group "Sales" and export to a CSV file:
```sh
GetADGroupMembersFSP.exe --group-name "Sales" --output-csv-file "C:\output\sales_members.csv"
```

## Output

The tool will display the following information in the console:

- Domain Name
- Group Name
- Total Members
- Unique Members
- Direct Group Memberships

Unique members will be displayed in green, and members with multiple memberships will be displayed in yellow.

### Sample Console Output

```
Domain Name: example.com
Group Name: Domain Users
Total Members: 150
Unique Members: 140
CN=John Doe,OU=Users,DC=example,DC=com, user, example\jdoe (Memberships: 1)
Direct Groups: Domain Users
CN=Jane Smith,OU=Users,DC=example,DC=com, user, example\jsmith (Memberships: 2)
Direct Groups: Domain Users, Sales
...
```

### Sample CSV Output

The CSV file will contain the following columns:

- DistinguishedName
- ObjectClass
- NTAccountName
- MembershipCount
- DirectGroups

#### Sample CSV Content

```
DistinguishedName,ObjectClass,NTAccountName,MembershipCount,DirectGroups
CN=John Doe,OU=Users,DC=example,DC=com,user,example\jdoe,1,Domain Users
CN=Jane Smith,OU=Users,DC=example,DC=com,user,example\jsmith,2,Domain Users|Sales
...

## License
This project is licensed under the MIT License. See the LICENSE file for details.
