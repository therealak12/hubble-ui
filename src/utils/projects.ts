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

  async setProjects(token: string) {
    const headers = {
      Authorization: 'Bearer ' + token,
    };
    const url = process.env.REACT_APP_HUBBLE_MIDDLEWARE_URL + '/projects' ?? '';

    try {
      const response = await fetch(url, { method: 'GET', headers: headers });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }

      const data: User = await response.json();
      this.projects = data.projects;

    } catch (error: any) {
      console.error('There was a problem with the fetch operation:', error.message);
    }
  }
}
