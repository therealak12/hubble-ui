export interface User {
  username: string;
  projects: Array<string>;
}

export class Projects {
  private static instance: Projects;
  private projects: Array<string> | null = null;

  public static getInstance(): Projects {
    if (!Projects.instance) {
      Projects.instance = new Projects();
    }

    return Projects.instance;
  }

  getProjects(): Array<string> | null {
    return this.projects;
  }

  manipulateUrl(url: string): string {
    const regex = /hubble/;
    const match: boolean = regex.test(url);
    if (match) {
      return url.replace('hubble', 'hubble-middleware');
    }
    return url;
  }

  async setProjects(token: string) {
    const headers = {
      Authorization: 'Bearer ' + token,
    };

    const baseUrl = this.manipulateUrl(window.location.origin);
    const url = baseUrl + '/projects';

    try {
      const response = await fetch(url, { method: 'GET', headers: headers });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const data: User = await response.json();
      this.projects = data.projects;
    } catch (error: any) {
      console.error(
        'There was a problem with the fetch operation:',
        error.message,
      );
    }
  }
}
