import os
import re
import shutil

README_FILE = 'README.md'
BACKUP_FILE = 'README_backup.md'
SECTION_TITLE = '## Project Legacy and Succession Planning'
SUBSECTION_TITLES = {
    '### Vision Statement': 'Placeholder for Vision Statement',
    '### Maintenance Guidelines': 'Placeholder for Maintenance Guidelines',
    '### Current Maintainers': ''
}

MAINTAINERS_TEMPLATE_FILE = 'maintainers_template.md'
MAINTAINERS_FILE = 'maintainers.md'


def update_readme():
    new_section = f"{SECTION_TITLE}\n\n"
    for title, content in SUBSECTION_TITLES.items():
        if title == '### Current Maintainers':
            # Read maintainers from the template file
            with open(MAINTAINERS_TEMPLATE_FILE, 'r') as file:
                maintainers_content = file.read()

            # Update the maintainers content
            maintainers_content = maintainers_content.strip()

            # Insert the updated maintainers content
            new_section += f"{title}\n\n{maintainers_content}\n\n"
        else:
            new_section += f"{title}\n\n{content}\n\n"

    if not os.path.exists(README_FILE):
        # Create a new README file with the section
        with open(README_FILE, 'w') as file:
            file.write(new_section.strip() + '\n')
    else:
        # Create a backup of the original README file
        shutil.copyfile(README_FILE, BACKUP_FILE)

        # Update or add to the README file
        with open(README_FILE, 'r') as file:
            content = file.read()

        # Regex to find existing section
        pattern = rf"{SECTION_TITLE}([\s\S]*?)(?=\n## |$)"
        if re.search(pattern, content):
            # Replace existing section
            updated_content = re.sub(pattern, new_section.strip(), content,
                                     flags=re.DOTALL)
        else:
            # Insert section after the last existing ## section
            last_section_match = re.search(r"(## .*?)(?=\n## |$)", content,
                                           flags=re.DOTALL)
            if last_section_match:
                insert_position = last_section_match.end()
                updated_content = (
                        content[:insert_position] + "\n\n"
                        + new_section.strip() + content[insert_position:]
                )
            else:
                # No sections found, append at the end
                updated_content = (content.strip() + "\n\n"
                                   + new_section.strip())

        # Write updated content back to the file
        with open(README_FILE, 'w') as file:
            file.write(updated_content.strip() + '\n')


if __name__ == '__main__':
    update_readme()
